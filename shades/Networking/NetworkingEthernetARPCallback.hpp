#ifndef NetworkingEthernetARPCallback_h
#define NetworkingEthernetARPCallback_h

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

#endif /* NetworkingEthernetARPCallback_h */
