//
//  main.cpp
//  sweep
//

#include <iostream>
#include <memory>
#include <thread>
#include <map>
#include <mutex>
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
};

std::map<IPv4Address, enum REPLY_STATE> query_results;
std::mutex query_results_mutex;

/*
 * Some interface types will get ethernet packets and some will only get IP.
 * If get an IP packet on an interface that captures ethernet (and above),
 * our callback will be called twice (once for ethernet and once for IP). We
 * can use the packet_id to avoid printing the packet twice.
 */
bool got_packet(size_t callback_id, void *data, NetworkingInput &net, PacketHeader &ph) {
    static size_t last_packet_id = SIZE_T_MAX; // Pick a default value that's not the same as the first packet id

    if (ph.packet_id() == last_packet_id) return true;

    PacketHeaderICMP &echo_reply = dynamic_cast<PacketHeaderICMP &>(ph);
    std::lock_guard<std::mutex> guard(query_results_mutex);

    // How do I get the IP?
    std::cout << "got one\n";

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
        net.ipv4_layer.send(dest, IPPROTO::ICMP, pb);
    } catch (...) {
        std::lock_guard<std::mutex> guard(query_results_mutex);
        query_results.emplace(dest, ARP_TIMEOUT);
    }
}

void ping_sweep(Networking &net, const IPv4AddressAndMask &range) {
    for(IPv4Address ip(range.addr); range.contains(ip); ip.ip_int = htonl(ntohl(ip.ip_int) + 1)) {
        ping_ip(net, ip);
    }
    std::this_thread::sleep_for(std::chrono::seconds(4));
    net.get_input().keep_running = false;
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
            pcap_filter = "icmp and src net " + ip_range.as_string();
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

    Networking net(net_in, bind_to);

    net.eth_layer.silent = true;
    net.ipv4_layer.silent = true;

    net_in.register_callback(typeid(PacketHeaderICMPEcho), got_packet);

#if 0
    struct bpf_program bpf_filter;
    pcap_t *pcap = netdriver.get_pcap(); // borrowed
    if (pcap_compile(pcap, &bpf_filter, pcap_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0 || pcap_setfilter(pcap, &bpf_filter) != 0) {
        pcap_perror(pcap, "");
        exit(1);
    }
#endif

    std::clog << "Sending ping query to all of " << ip_range.as_string() << " from " << bind_to.as_string() << " on " << iface << "\n---\n";

    std::thread query_thread(ping_sweep, std::ref(net), std::ref(ip_range));
    net_in.run();
    query_thread.join();

    bool got_reply = false;
    for (const auto &i : query_results) {
        std::cout << i.first << " = " ;
        switch (i.second) {
            case UNKNOWN:
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
