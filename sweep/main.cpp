//
//  main.cpp
//  sweep
//

#include <iostream>
#include <memory>
#include <map>
#include <chrono>

#include <unistd.h>
#include <sys/types.h>

#include "NetDriverPCAP.hpp"
#include "Networking.hpp"
#include "PacketHeaders.hpp"
#include "PacketQueue.hpp"
#include "OSNetwork.hpp"

enum REPLY_STATE {
    UNKNOWN = 0,
    REPLY = 1,
    ARP_TIMEOUT = 2,
    STEALTH = 3,
};

std::map<IPv4Address, enum REPLY_STATE> query_results;

bool got_packet(size_t callback_id, void *data, NetworkingInput &net, PacketHeader &ph) {
    PacketHeaderICMP &icmp = dynamic_cast<PacketHeaderICMP &>(ph);
    if (icmp.type() != ICMP::ECHOREPLY || icmp.code() != 0) return true;

    PacketHeaderICMPEcho echo(icmp.next_header_offset());
    if (echo.seq() != 1|| echo.ident() != 1) return true;

    IPv4Address source_ip;

    /*
     PCAP interfaces could be layer 2 or layer 3, and there's no API to walk
     "up" the packet chain, so we have to start at the top and walk back down.
     */
    if (ph.backing_buffer().header_type == PacketBuffer::HEADER_ETHERNET) {
        PacketHeaderEthernet eth(ph.backing_buffer());
        PacketHeaderIPv4 ipv4(eth.next_header_offset());
        source_ip = ipv4.source();
    } else if (ph.backing_buffer().header_type == PacketBuffer::HEADER_IPV4) {
        PacketHeaderIPv4 ipv4(ph.backing_buffer());
        source_ip = ipv4.source();
    }

    if (!source_ip) {
        // We shouldn't get here.
        return true;
    }

    query_results[source_ip] = REPLY;

    return true;
}

void ping_ip(Networking &net, const IPv4Address &dest) {
    const int ECHO_DATA_SIZE = 20;
    PacketBuffer pb(PacketHeaderICMP::minimum_header_size() + PacketHeaderICMPEcho::minimum_header_size() + ECHO_DATA_SIZE);
    PacketHeaderICMP icmp(pb);
    PacketHeaderICMPEcho echo(icmp.next_header_offset());

    auto echo_data = echo.next_header_offset();
    memset(echo_data.data(), 0, ECHO_DATA_SIZE);

    echo.seq = 1;
    echo.ident = 1;

    icmp.type = ICMP::ECHO;
    icmp.code = 0;
    icmp.update_checksum();

    try {
        net.ipv4_layer->send(dest, IPPROTO::ICMP, pb);
        query_results[dest] = STEALTH;
    } catch (...) {
        query_results[dest] = ARP_TIMEOUT;
    }
}

void usage() {
    std::cout << "sweep: Ping a bunch of things.\n\n";
    std::cout << "usage: shadescap [-h] [-v] -i interface -p CIDR\n";
    std::cout << "-h             This help\n";
    std::cout << "-p CIDR        Subnet to query\n";
    exit(1);
}

int main(int argc, const char *argv[]) {
    std::string iface;
    std::string pcap_filter;
    IPv4AddressAndMask ip_range;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h")) {
            usage();
        } else if (!strcmp(argv[i], "-p")) {
            ip_range = argv[i + 1];
            pcap_filter = "arp or (icmp and src net " + ip_range.as_string() + ")";
            i++;
        } else {
            usage();
        }
    }

    if (!ip_range.addr.ip_int || !ip_range.mask.mask) usage();

    IPv4Address source_ip = OSNetwork::get_local_addr_for_remote(htonl(ntohl(ip_range.addr.ip_int) + 1));
    IPv4AddressAndMask bind_to;
    auto interfaces = OSNetwork::get_interfaces();
    for (const auto &i : *interfaces) {
        if (i.second.ipv4_address.addr == source_ip) {
            iface = i.second.name;
            bind_to = i.second.ipv4_address;
        }
    }

    if (iface.empty()) {
        std::cerr << "Unable to find interface to use\n";
        return 1;
    }

    NetDriverPCAP netdriver(iface);
    NetworkingInput net_in(netdriver);

    Networking net(net_in, NetworkingLayers::IP, bind_to);

    net.eth_layer.silent = true;
    net.ipv4_layer->silent = true;

    // Don't currently trigger callbacks for ICMP Echo, so use ICMP
    net_in.register_callback(typeid(PacketHeaderICMP), got_packet);

    // This is optional but speeds things up on a busy host.
    struct bpf_program bpf_filter;
    pcap_t *pcap = netdriver.get_pcap(); // borrowed
    if (pcap_compile(pcap, &bpf_filter, pcap_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0 || pcap_setfilter(pcap, &bpf_filter) != 0) {
        pcap_perror(pcap, "");
        exit(1);
    }

    std::clog << "Sending ping query to all of " << ip_range.as_string() << " from " << bind_to.as_string() << " on " << iface << "\n---\n";

    for(IPv4Address ip(ip_range.addr); ip_range.contains(ip); ip.ip_int = htonl(ntohl(ip.ip_int) + 1)) {
        ping_ip(net, ip);
        net.process_one();
    }

    auto start = std::chrono::steady_clock::now();
    while(std::chrono::steady_clock::now() - start < std::chrono::seconds(2)) {
        net.process_one();
    }

    bool got_reply = false;
    for (const auto &i : query_results) {
        std::cout << i.first << " = " ;
        switch (i.second) {
            case UNKNOWN:
                std::cout << "Unknown\n"; // Shouldn't get here
                break;
            case STEALTH:
                std::cout << "Stealth?\n";
                break;
            case ARP_TIMEOUT:
                std::cout << "No reply\n";
                break;
            case REPLY:
                std::cout << "Reply received\n";
                got_reply = true;
                break;
            default:
                break;
        }
    }

    return got_reply ? 0 : 1;
}
