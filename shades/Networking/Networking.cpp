#include "Networking.hpp"

#include <netinet/in_systm.h>
#include <ifaddrs.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#else
#include <net/if_dl.h>
#endif

Networking::Networking(NetDriver &nd, const IPv4AddressAndMask my_address_and_mask) :
    net_driver(nd),
    net_in(nd),
    promiscuous(false),
    ipv4_layer(*this),
    eth_layer(*this)
{
    // assign ip? dhcp?
    my_mac = get_interface_mac(net_driver.get_ifname());
    my_subnet_mask = my_address_and_mask.mask;
    my_ip = my_address_and_mask.addr;
    
    // These two will never be called if our net_in doesn't capture Ethernet (layer 2)
    net_in.register_callback(typeid(PacketHeaderEthernet),
                             [this](NetworkingInput &ni, PacketHeader &p1, PacketHeader &pN, void *d) { return ethernet_callback(ni, p1, pN, d); }
                             );
    net_in.register_callback(typeid(PacketHeaderIPv4),
                             [this](NetworkingInput &ni, PacketHeader &p1, PacketHeader &pN, void *d) { return ipv4_callback(ni, p1, pN, d); }
                             );
}

// Implements ethernet promiscuous mode.
bool Networking::ethernet_callback(NetworkingInput &, PacketHeader &p1, PacketHeader &pN, void *) {
    auto &eth = dynamic_cast<PacketHeaderEthernet &>(pN);
    if (eth.dest()[0] & ETHERNET_MULTICAST_BIT || eth.dest() == my_mac) return eth_layer.process(eth);
    if (promiscuous) return true;
    return false;
}

// IPv4 promiscuous mode check before hading off to the IPv4 layer. Maybe should be handled there?
bool Networking::ipv4_callback(NetworkingInput &, PacketHeader &p1, PacketHeader &pN, void *) {
    auto &ip = dynamic_cast<PacketHeaderIPv4 &>(pN);
    if (ip.dest() == my_ip || ip.dest() == 0xFFFFFFFF) return ipv4_layer.process(ip); // Missing multicast blocks
    if (promiscuous) return true;
    return false;
}

void Networking::run() {
    net_in.keep_running = true;
    while(net_in.keep_running) {
        if (auto *buf = packet_queue.get_readable()) {
            net_in.process_one(*buf);
            packet_queue.put_writable(buf); // We're done with it.
        } else {
            net_in.process_one();
        }
    }
}

NetworkingInput &Networking::input() {
    return net_in;
}

#ifdef SIOCGIFHWADDR
EthernetAddress Networking::get_interface_mac(const std::string_view ifn) {
    int fd;
    struct ifreq ifr;
    EthernetAddress ea;
    
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) throw std::runtime_error("Failed to open socket");
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifn.data(), IFNAMSIZ - 1);
    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        throw std::runtime_error(std::string("Failed to get ethernet address for ") + ifn.data());
    }
    close(fd);
    
    memcpy(ea.data(), ifr.ifr_hwaddr.sa_data, ea.size());
    return ea;
}
#elif defined(__FreeBSD__) || ( defined(__APPLE__) && defined(__MACH__) )
EthernetAddress Networking::get_interface_mac(const std::string_view ifn) {
    struct ifaddrs *ifap;
    EthernetAddress ea;
    
    if (getifaddrs(&ifap) == 0) {
        struct ifaddrs *p;
        for (p = ifap; p; p = p->ifa_next) {
            if ((p->ifa_addr->sa_family == AF_LINK) && (p->ifa_name == ifn)) {
                struct sockaddr_dl sdp;
                if (p->ifa_addr->sa_len != sizeof(struct sockaddr_dl)) throw std::runtime_error("sa_len value unexpected!");
                memcpy(&sdp, p->ifa_addr, sizeof(struct sockaddr_dl)); // Avoid aliasing
                memcpy(ea.data(), sdp.sdl_data + sdp.sdl_nlen, ea.size());
                freeifaddrs(ifap);
                return ea;
            }
        }
        freeifaddrs(ifap);
    }
    throw std::runtime_error(std::string("Failed to get ethernet address for ") + ifn.data());
}
#else
#error Do not know how to get MAC address on this platform.
#endif
