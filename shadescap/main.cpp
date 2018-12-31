//
//  main.cpp
//  shadescap
//

#include <iostream>
#include <memory>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include "NetDriverPCAP.hpp"
#include "Networking.hpp"
#include "PacketHeaders.hpp"
#include "PacketQueue.hpp"

/*
 * Some interface types will get ethernet packets and some will only get IP.
 * If get an IP packet on an interface that captures ethernet (and above),
 * our callback will be called twice (once for ethernet and once for IP). We
 * can use the packet_id to avoid printing the packet twice.
 */
bool print_packet(size_t callback_id, void *data, NetworkingInput &net, PacketHeader &ph) {
    static size_t last_packet_id = SIZE_T_MAX; // Pick a default value that's not the same as the first packet id

    if (ph.packet_id() == last_packet_id) return true;

    last_packet_id = ph.packet_id();
    std::clog << ph;

    auto nh = ph.recalculate_next_header();
    while(nh) {
        std::clog << *nh;
        nh = nh->recalculate_next_header();
    }

    std::clog << "---\n";
    return true;
}

void usage() {
    std::cout << "shadescap: Print network packet headers.\n\n";
    std::cout << "usage: shadescap [-h] [-v] [-i interface] [-Z username] [pcap filter]\n";
    std::cout << "-h             This help\n";
    std::cout << "-v             Print ethernet headers (if available)\n";
    std::cout << "-i interface   Capture on this interface (default: \"any\")\n";
    std::cout << "-Z username    setuid to this user and setgid to user's default group\n";
    std::cout << "[pcap filter]  Capture packets matching this filter; see man pcap-filter\n";
    exit(1);
}

int main(int argc, const char *argv[]) {
    std::string iface = "any";
    std::string pcap_filter;
    bool capture_eth = false;
    uid_t new_uid = 0, new_gid = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h")) {
            usage();
        } else if (!strcmp(argv[i], "-v")) {
            capture_eth = true;
        } else if (!strcmp(argv[i], "-i")) {
            if (i + 1 >= argc) usage();
            iface = argv[i + 1];
            i++;
        } else if (!strcmp(argv[i], "-Z")) {
            if (i + 1 >= argc) usage();
            struct passwd *pwd = getpwnam(argv[i + 1]);
            if (!pwd) {
                std::cerr << "Unknown user: " << argv[i + 1] << "\n";
                exit(1);
            }
            new_uid = pwd->pw_uid;
            new_gid = pwd->pw_gid;
            i++;
        } else if (argv[i][0] == '-') {
            usage();
        } else {
            bool added_space = false;
            for (; i < argc; i++) {
                pcap_filter += argv[i];
                pcap_filter += ' ';
                added_space = true;
            }
            if (added_space) pcap_filter.pop_back();
            break;
        }
    }

    NetDriverPCAP netdriver(iface);
    NetworkingInput net_in(netdriver);

    if (capture_eth) net_in.register_callback(typeid(PacketHeaderEthernet), print_packet);
    net_in.register_callback(typeid(PacketHeaderIPv4), print_packet);
    //net_in.register_callback(typeid(PacketHeaderIPv6), print_packet);

    if (new_uid) {
        if (setgid(new_gid) != 0 || setuid(new_uid) != 0) throw std::runtime_error("Failed to setuid/setgid!");
    }

    if (!pcap_filter.empty()) {
        struct bpf_program bpf_filter;
        pcap_t *pcap = netdriver.get_pcap(); // borrowed
        if (pcap_compile(pcap, &bpf_filter, pcap_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0 || pcap_setfilter(pcap, &bpf_filter) != 0) {
            pcap_perror(pcap, "");
            exit(1);
        }
    }

    std::clog << "Listening on " << netdriver.get_ifname() << " for \"" << pcap_filter << "\"\n---\n";

    net_in.run();

    return 0;
}
