#include <iostream>
#include <memory>

#include <unistd.h>

#include "NetDriverPCAP.hpp"
#include "NetDriverUTun.hpp"
#include "Networking.hpp"
#include "PacketHeaders.hpp"
#include "PacketQueue.hpp"
#include "StackTracePrinter.hpp"

void on_terminate() {
    StackTracePrinter<50> stp;
    stp();
    exit(1);
}

bool print_icmp(NetworkingInput &ni, PacketHeader &p1, PacketHeader &pN, void *) {
    //PacketHeaderICMPEcho &icmp = dynamic_cast<PacketHeaderICMPEcho &>(pN);
    
    std::cout << p1;
    //PacketHeader *p = &p1;
    /*while(p->next_header()) {
        p = p->next_header();
        std::cout << *p;
    }*/
    
    //ni.stop_running();
    return true;
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

#ifdef FORCE_PCAP
     my_ip = "192.168.0.254/24";
     default_route = "192.168.0.1";
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
        netdriver = std::make_unique<NetDriverPCAP>(iface);
    } else {
#ifdef FORCE_PCAP
        netdriver = std::make_unique<NetDriverPCAP>(iface);
#else
        netdriver = std::make_unique<NetDriverUTun>("0");
#endif
    }

    Networking net(*netdriver.get(), {my_ip}, network_init_command);
    
    if (new_uid || new_gid) {
        if (setgid(new_gid) != 0 || setuid(new_uid) != 0) throw std::runtime_error("Failed to setuid/setgid!");
    }
    
    //net.input().register_callback(typeid(PacketHeaderICMPEcho), print_icmp);
    net.ipv4_layer.routes.set(0, 0, IPv4Address(default_route));
    
    std::clog << "net is on " << netdriver->get_ifname() << ", hwaddr " << net.my_mac << ", IPv4 " << net.my_ip << "\n";
    
    net.run();

    return 0;
}
