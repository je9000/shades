#include <iostream>
#include <memory>

#include <unistd.h>

#include "NetDriverPCAP.hpp"

#ifdef __APPLE__
#include "NetDriverUTun.hpp"
#endif

#include "Networking.hpp"
#include "PacketHeaders.hpp"
#include "PacketQueue.hpp"
#include "StackTracePrinter.hpp"
#include "Networking/NetworkingTCP.hpp"

void on_terminate() {
    StackTracePrinter<50> stp;
    std::clog << stp;
    exit(1);
}

#ifdef DEBUG_TCP_PACKETS
bool print_debug_tcp(size_t callback_id, void *data, NetworkingInput &net, PacketHeader &ph) {
    PacketHeaderTCP &tcp = dynamic_cast<PacketHeaderTCP &>(ph);
    std::clog << tcp << "\n";
    return true;
}
#endif

TCPSessionAction print_tcp(TCPSessionEvent event, const NetworkFlowTCP &flow, TCPSession *session, const PacketHeaderTCP &tcp) {
    //std::clog << "Got TCP event " << event << "\n";
    if (event == CONNECTION_CLOSING) return SESSION_FIN;
    if (event == DATA) {
        auto p = tcp.next_header_offset();
        std::string data((char *)p.data(), p.size());
        /*std::clog << "Got data: ";
        auto flags = std::clog.flags();
        std::clog << std::hex << std::setfill('0');
        for(char c : data) {
            if (isgraph(c)) {
                std::clog << c;
            } else {
                std::clog << "\\x" << std::setw(2) << static_cast<uint32_t>(c);
            }
        }
        std::clog << '\n';
        std::clog.flags(flags);*/
        session->send_data(data);
    }
    return SESSION_OK;
}

int main(int argc, const char *argv[]) {
#ifndef DEBUG
    std::set_terminate(on_terminate);
#endif
    
    std::unique_ptr<NetDriver> netdriver;
    std::string iface = "en0";
    std::string my_ip = "172.16.0.2/32";
    std::string default_route = "172.16.0.1";
    std::string network_init_command = "ifconfig $_IFNAME $_IPV4_ADDRESS $_IPV4_ADDRESS netmask $_IPV4_NETMASK";

#define FORCE_PCAP
#define VM

#ifdef FORCE_PCAP
#ifdef VM
    my_ip = "10.100.100.3/24";
    default_route = "10.100.100.1";
    iface = "vboxnet0";
#else
    my_ip = "192.168.0.254/24";
    default_route = "192.168.0.1";
#endif
    network_init_command = "";
#endif

    int new_uid = 0, new_gid = 0;

    if (argc > 4) {
        iface = argv[1];
        my_ip = argv[2];
        default_route = argv[3];
        if (sscanf(argv[4], "%d:%d", &new_uid, &new_gid) != 2) {
            std::cerr << "Can't parse new uid:gid\n";
            return 1;
        }
        network_init_command = "";
        netdriver = std::make_unique<NetDriverPCAP>(iface);
    } else {
#if defined(FORCE_PCAP) || !defined(__APPLE__)
        netdriver = std::make_unique<NetDriverPCAP>(iface);
#else
        netdriver = std::make_unique<NetDriverUTun>("0");
#endif
    }

    NetworkingInput net_in(*netdriver.get());

#ifdef DEBUG_TCP_PACKETS
    net_in.register_callback(typeid(PacketHeaderTCP), print_debug_tcp);
#endif

    Networking net(net_in, NetworkingLayers::TCP, {my_ip}, network_init_command);
    
    if (new_uid || new_gid) {
        if (setgid(new_gid) != 0 || setuid(new_uid) != 0) throw std::runtime_error("Failed to setuid/setgid!");
    }

    net.ipv4_layer->routes.set(0, 0, IPv4Address(default_route), netdriver->get_mtu());
    net.tcp_layer->register_listener(PROTO_IPv4, 3389, print_tcp);
    
    std::clog << "net is on " << netdriver->get_ifname() << ", hwaddr " << net.my_mac << ", IPv4 " << net.my_ip << ", MTU " << netdriver->get_mtu() << "\n";
    
    net.run();

    return 0;
}
