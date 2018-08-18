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
    net_in.register_callback(typeid(PacketHeaderICMPEcho),
                             [this](NetworkingInput &ni, PacketHeader &p1, PacketHeader &pN, void *d) { return icmp_echo_callback(ni, p1, pN, d); }
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

// Needs to be moved to an IPv4 layer callback so fragmentation is handled for us.
bool Networking::icmp_echo_callback(NetworkingInput &, PacketHeader &p1, PacketHeader &pN, void *) {
    //auto &echo = dynamic_cast<PacketHeaderICMPEcho &>(pN);
    auto &eth = dynamic_cast<PacketHeaderEthernet &>(p1);
    PacketHeaderIPv4 ip(eth.next_header_offset());
    PacketHeaderICMP icmp(ip.next_header_offset());
    
    PacketBuffer pb = eth.backing_buffer(); // copy packet
    
    PacketHeaderEthernet new_eth(pb);
    PacketHeaderIPv4 new_ip(new_eth.next_header_offset());
    PacketHeaderICMP new_icmp(new_ip.next_header_offset());
    //PacketHeaderICMPEcho new_echo(new_icmp.next_header_offset()); // We just copy from the source.
    
    new_eth.source = my_mac;
    
    if (my_subnet_mask.same_network(my_ip, ip.source())) {
        new_eth.dest = eth.source();
    } else {
        auto router_ip = ipv4_layer.routes.get(ip.source());
        try {
            new_eth.dest = arp_resolve(router_ip);
        } catch (...) {
            // ARP never resolved, nowhere to send this.
            return false;
        }
    }
    
    new_ip.source = my_ip;
    new_ip.dest = ip.source();
    
    new_icmp.type = ICMP::ECHOREPLY;
    // data is copied because we copied the packet and the headers are the same size.
    new_icmp.update_checksum();
    
    net_driver.send(pb);
    return true;
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

NetworkingInput &Networking::input() { return net_in; }

EthernetAddress Networking::arp_resolve(const IPv4Address &ip) {
    try {
        return eth_layer.arp_table.at(ip);
    } catch (...) {
        // Send an ARP query, listen for answers.
        
        PacketBuffer pb;
        PacketHeaderEthernet eth(pb);
        eth.source = my_mac;
        eth.dest = ETHER_ADDR_BROADCAST;
        eth.ether_type = ETHERTYPE::ARP;
        PacketHeaderARP arp(eth.next_header_offset());
        arp.sender_mac = my_mac;
        arp.sender_ip = my_ip;
        arp.oper = ARP::REQUEST;
        arp.target_ip = ip;
        arp.target_mac = ETHER_ADDR_ZERO;
        arp.hlen = EthernetAddress::size();
        arp.plen = IPv4Address::size();
        arp.htype = ETHERTYPE::ETHERNET;
        arp.ptype = ETHERTYPE::IP;
        
        pb.set_valid_size(eth.header_size() + arp.header_size());
        
        net_driver.send(pb);
        
        // buffer packets for a while looking for reply.
        auto arp_search_start = std::chrono::steady_clock::now();
        while(true) {
            if (std::chrono::steady_clock::now() - arp_search_start > ARP_QUERY_TIMEOUT) {
                break;
            }
            auto *writable = packet_queue.get_writable();
            if (!writable) throw std::bad_alloc();
            net_driver.recv(*writable); // recv directly so we don't trigger callbacks.
            
            try {
                PacketHeaderEthernet ether(*writable);
                ether.check();
                if (ether.ether_type() != ETHERTYPE::ARP) {
                    packet_queue.put_readable(writable);
                    continue;
                }
                
                PacketHeaderARP maybe_arp_reply(ether.next_header_offset());
                maybe_arp_reply.check();
                if (maybe_arp_reply.oper() == ARP::REPLY) {
                    if (maybe_arp_reply.sender_ip() == ip) {
                        eth_layer.arp_table.insert_or_assign(ip, maybe_arp_reply.sender_mac());
                        return maybe_arp_reply.sender_mac();
                    }
                    packet_queue.put_readable(writable);
                    continue;
                }
            } catch(...) {
                packet_queue.put_readable(writable);
                continue;
            }
        }
    }
    throw std::runtime_error("ARP query timeout");
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
