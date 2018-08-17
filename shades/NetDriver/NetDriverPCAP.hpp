#ifndef NetDriverPCAP_h
#define NetDriverPCAP_h

#include <algorithm>
#include <exception>

#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>

#include "NetDriver.hpp"
#include "PacketBuffer.hpp"

class NetDriverPCAP: public NetDriver {
private:
    pcap_t *pcap = nullptr;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int datalink_header = HEADER_UNKNOWN;
    size_t pcap_header_size = 0;
    
    PacketBufferHeaderType guess_loop_header_type(const u_char *);
    PacketBufferHeaderType guess_raw_header_type(const u_char *);
public:
    NetDriverPCAP(const std::string_view);
    ~NetDriverPCAP();
    void send(PacketBuffer &);
    bool recv(PacketBuffer &);
    size_t header_size() { return pcap_header_size; }
};

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
}

NetDriverPCAP::~NetDriverPCAP() {
    pcap_close(pcap);
}

void NetDriverPCAP::send(PacketBuffer &pb) {
    auto r = pcap_inject(pcap, pb.data(), pb.size());
    if (r != pb.size()) throw std::runtime_error("Unable to send all data");
}

PacketBufferHeaderType NetDriverPCAP::guess_loop_header_type(const u_char *data) {
    uint32_t loop_header;
    memcpy(&loop_header, data, sizeof(loop_header));
    if (datalink_header == DLT_LOOP) loop_header = ntohl(loop_header);
    switch (loop_header) {
        case 2:
            return HEADER_IPV4;
            
        case 24:
        case 28:
        case 30:
            return HEADER_IPV6;
            
        default:
            return HEADER_UNKNOWN;
    }
}

PacketBufferHeaderType NetDriverPCAP::guess_raw_header_type(const u_char *data) {
    uint8_t ip_header;
    memcpy(&ip_header, data, sizeof(ip_header));
    // The first 4 bits are the IP version.
    switch (ip_header >> 4) {
        case 4:
            return HEADER_IPV4;
        case 6:
            return HEADER_IPV6;
        default:
            return HEADER_UNKNOWN;
    }
    
}

bool NetDriverPCAP::recv(PacketBuffer &pb) {
    struct pcap_pkthdr *header;
    u_char *data;
    auto r = pcap_next_ex(pcap, &header, const_cast<const u_char **>(&data));
    if (r == 0) return false; // Timeout
    if (r < 0 || header->caplen == 0) throw std::runtime_error("Read error");
    if (header->caplen > header->len) throw std::runtime_error("PCAP buffer too small");
    
    PacketBufferHeaderType pb_header_type;
    
    switch (datalink_header) {
        case DLT_EN10MB:
            pb_header_type = HEADER_ETHERNET;
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
            pb_header_type = HEADER_UNKNOWN;
    }
    
    if (header->caplen <= pcap_header_size) throw std::out_of_range("caplen too small for header");
    pb.copy_from(data + pcap_header_size, header->caplen - pcap_header_size, pb_header_type);
    return true;
}

#endif /* NetDriverPCAP_h */
