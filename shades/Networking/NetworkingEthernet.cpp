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
