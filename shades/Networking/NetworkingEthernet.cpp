#include "Networking.hpp"
#include "NetworkingEthernet.hpp"
#include "PacketHeaders.hpp"

bool NetworkingEthernet::process(PacketHeaderEthernet &packet) {
    return process_next_header(packet);
}

void NetworkingEthernet::register_callback(const std::type_info &packet_type, const NetworkingEthernetInputCallback &callback, void *data) {
    ethernet_callbacks[packet_type].push_back({callback, data});
}

bool NetworkingEthernet::process_next_header(PacketHeaderEthernet &packet) {
    decltype(ethernet_callbacks)::const_iterator callbacks;
    switch (packet.ether_type()) {
        case ETHERTYPE::IP:
            callbacks = ethernet_callbacks.find(typeid(PacketHeaderIPv4));
            break;
            
            /*case ETHERTYPE::IPV6:
             callbacks = ethernet_callbacks.find(typeid(PacketHeaderIPv6));
             break;*/
            
        case ETHERTYPE::ARP:
            arp_callback(packet);
            callbacks = ethernet_callbacks.find(typeid(PacketHeaderARP));
            break;
            
        default:
            stats.unknown_protocols++;
            return true;
    }
    if (callbacks == ethernet_callbacks.end()) return true;
    for (auto &cb : callbacks->second) {
        cb.func(*this, packet, cb.data);
    }
    return true;
}

void NetworkingEthernet::arp_callback(PacketHeaderEthernet &eth) {
    PacketHeaderARP arp(eth.next_header_offset());
    if (arp.oper() == ARP::REPLY) {
        arp_table.insert_or_assign(arp.sender_ip(), arp.sender_mac());
    } else if (arp.oper() == ARP::REQUEST) {
        if (arp.target_ip() == networking.my_ip) {
            arp_table.insert_or_assign(arp.sender_ip(), arp.sender_mac());
            
            PacketBuffer pb;
            PacketHeaderEthernet new_eth(pb);
            PacketHeaderARP new_arp(new_eth.next_header_offset());
            new_eth.build(networking.my_mac, eth.source(), ETHERTYPE::ARP);
            
            new_arp.target_mac = arp.sender_mac();
            new_arp.target_ip = arp.sender_ip();
            
            new_arp.sender_mac = networking.my_mac;
            new_arp.sender_ip = networking.my_ip;
            
            new_arp.oper = ARP::REPLY;
            
            new_arp.hlen = EthernetAddress::size();
            new_arp.plen = IPv4Address::size();
            new_arp.htype = ETHERTYPE::ETHERNET;
            new_arp.ptype = ETHERTYPE::IP;
            
            pb.set_valid_size(eth.header_size() + arp.header_size());
            networking.net_driver.send(pb);
        }
    }
}

EthernetAddress NetworkingEthernet::arp_resolve(const IPv4Address &ip) {
    try {
        return arp_table.at(ip);
    } catch (...) {
        // Send an ARP query, listen for answers.
        
        PacketBuffer pb;
        PacketHeaderEthernet eth(pb);
        eth.source = networking.my_mac;
        eth.dest = ETHER_ADDR_BROADCAST;
        eth.ether_type = ETHERTYPE::ARP;
        PacketHeaderARP arp(eth.next_header_offset());
        arp.sender_mac = networking.my_mac;
        arp.sender_ip = networking.my_ip;
        arp.oper = ARP::REQUEST;
        arp.target_ip = ip;
        arp.target_mac = ETHER_ADDR_ZERO;
        arp.hlen = EthernetAddress::size();
        arp.plen = IPv4Address::size();
        arp.htype = ETHERTYPE::ETHERNET;
        arp.ptype = ETHERTYPE::IP;
        
        pb.set_valid_size(eth.header_size() + arp.header_size());
        
        networking.net_driver.send(pb);
        
        // buffer packets for a while looking for reply. This needs to be more generalized.
        auto arp_search_start = std::chrono::steady_clock::now();
        while(true) {
            if (std::chrono::steady_clock::now() - arp_search_start > ARP_QUERY_TIMEOUT) {
                break;
            }
            auto *writable = networking.packet_queue.get_writable();
            if (!writable) throw std::bad_alloc();
            networking.net_driver.recv(*writable); // recv directly so we don't trigger callbacks.
            
            try {
                PacketHeaderEthernet ether(*writable);
                ether.check();
                if (ether.ether_type() != ETHERTYPE::ARP) {
                    networking.packet_queue.put_readable(writable);
                    continue;
                }
                
                PacketHeaderARP maybe_arp_reply(ether.next_header_offset());
                maybe_arp_reply.check();
                if (maybe_arp_reply.oper() == ARP::REPLY) {
                    if (maybe_arp_reply.sender_ip() == ip) {
                        arp_table.insert_or_assign(ip, maybe_arp_reply.sender_mac());
                        return maybe_arp_reply.sender_mac();
                    }
                    networking.packet_queue.put_readable(writable);
                    continue;
                }
            } catch(...) {
                networking.packet_queue.put_readable(writable);
                continue;
            }
        }
    }
    throw std::runtime_error("ARP query timeout");
}

void NetworkingEthernet::send(const IPv4Address &dest, IPv4RouteTable &routes, const ETHERTYPE::ETHERTYPE type, PacketBuffer &pb) {
    EthernetAddress dest_mac;
    if (networking.my_subnet_mask.same_network(networking.my_ip, dest)) {
        dest_mac = arp_resolve(dest);
    } else {
        auto router_ip = routes.get(dest);
        dest_mac = arp_resolve(router_ip);
    }
    
    send(dest_mac, type, pb);
}

void NetworkingEthernet::send(const EthernetAddress &dest, const ETHERTYPE::ETHERTYPE type, PacketBuffer &pb) {
    pb.unreserve_space(PacketHeaderEthernet::minimum_header_size());
    PacketHeaderEthernet eth(pb);
    
    eth.build(networking.my_mac, dest, type);
    
    networking.net_driver.send(pb);
}
