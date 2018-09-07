#include <algorithm>
#include <exception>

#include <pcap.h>
#include <arpa/inet.h>

#include "NetDriverPCAP.hpp"

NetDriverPCAP::NetDriverPCAP(const std::string_view ifn) : NetDriver(ifn) {
    pcap = pcap_open_live(ifname.data(), MAX_FRAME_SIZE, 1, 1, error_buffer);
    if (pcap == NULL) {
        throw std::runtime_error(std::string("Could not open interface: ") + error_buffer);
    }
    //pcap_setdirection(pcap, PCAP_D_IN); // Doesn't really matter if it fails.
    
    // See: https://www.tcpdump.org/linktypes.html
    datalink_header = pcap_datalink(pcap);
    switch (datalink_header) {
        case DLT_EN10MB:
            break;
            
        case DLT_NULL:
        case DLT_LOOP:
            pcap_header_size = 4; // NULL and LOOP have a 4-byte header.
            break;
            
        case DLT_RAW:
            break;
            
        case PCAP_ERROR_NOT_ACTIVATED:
            throw std::runtime_error("Failed to get pcap_datalink");
            
        default:
            throw std::runtime_error("Unsupported pcap_datalink type");
    }
    
    mtu = get_mtu();
}

NetDriverPCAP::~NetDriverPCAP() {
    pcap_close(pcap);
}

bool NetDriverPCAP::is_layer3_interface() {
    if (datalink_header == DLT_EN10MB) return false;
    return true;
}

void NetDriverPCAP::send(PacketBuffer &pb, size_t len) {
    size_t send_len;
    size_t unreserved_change = 0;
    if (len) {
        if (len > pb.size()) throw std::out_of_range("len > pb.size()");
        send_len = len;
    } else {
        send_len = pb.size();
    }
    
    if (datalink_header == DLT_LOOP || datalink_header == DLT_NULL) {
        uint32_t ip_version;
        switch (guess_raw_header_type(pb.data())) {
            case PacketBuffer::HEADER_IPV4:
                ip_version = 2; // AF_INET, the docs say to use a number
                break;
                
            case PacketBuffer::HEADER_IPV6:
                ip_version = 30; // AF_INET6
                break;
                
            default:
                throw std::runtime_error("Unsupported packet type");;
        }
        unreserved_change = sizeof(ip_version);
        pb.take_reserved_space(sizeof(ip_version));
        send_len += sizeof(ip_version);
        if (datalink_header == DLT_LOOP) ip_version = htonl(ip_version);
        memcpy(pb.data(), &ip_version, sizeof(ip_version));
    }
    auto r = pcap_inject(pcap, pb.data(), send_len);
    if (r != send_len) throw std::runtime_error("Unable to send all data");
}

PacketBuffer::HEADER_TYPE NetDriverPCAP::guess_loop_header_type(const u_char *data) {
    uint32_t loop_header;
    memcpy(&loop_header, data, sizeof(loop_header));
    if (datalink_header == DLT_LOOP) loop_header = ntohl(loop_header);
    switch (loop_header) {
        case 2: // AF_INET
            return PacketBuffer::HEADER_IPV4;
            
        case 24:
        case 28:
        case 30: // AF_INET6, but the docs for pcap say to check all 3.
            return PacketBuffer::HEADER_IPV6;
            
        default:
            return PacketBuffer::HEADER_UNKNOWN;
    }
}

PacketBuffer::HEADER_TYPE NetDriverPCAP::guess_raw_header_type(const u_char *data) {
    uint8_t ip_header;
    memcpy(&ip_header, data, sizeof(ip_header));
    // The first 4 bits are the IP version.
    switch (ip_header >> 4) {
        case 4:
            return PacketBuffer::HEADER_IPV4;
        case 6:
            return PacketBuffer::HEADER_IPV6;
        default:
            return PacketBuffer::HEADER_UNKNOWN;
    }
}

bool NetDriverPCAP::recv(PacketBuffer &pb) {
    struct pcap_pkthdr *header;
    u_char *data;
    auto r = pcap_next_ex(pcap, &header, const_cast<const u_char **>(&data));
    if (r == 0) return false; // Timeout
    if (r < 0 || header->caplen == 0) throw std::runtime_error("Read error");
    if (header->caplen > header->len) throw std::runtime_error("PCAP buffer too small");
    
    PacketBuffer::HEADER_TYPE pb_header_type;
    
    switch (datalink_header) {
        case DLT_EN10MB:
            pb_header_type = PacketBuffer::HEADER_ETHERNET;
            break;
            
        case DLT_NULL:
        case DLT_LOOP:
            pb_header_type = guess_loop_header_type(data);
            break;
            
        case DLT_RAW:
            pb_header_type = guess_raw_header_type(data);
            break;
            
        default:
            // Shouldn't get here!
            pb_header_type = PacketBuffer::HEADER_UNKNOWN;
    }
    
    if (header->caplen <= pcap_header_size) throw std::out_of_range("caplen too small for header");
    pb.copy_from(data + pcap_header_size, header->caplen - pcap_header_size, pb_header_type);
    return true;
}
