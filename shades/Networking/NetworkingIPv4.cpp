#include "Networking.hpp"
#include "NetworkingIPv4.hpp"
#include "PacketHeaders.hpp"

void IPv4FlowPendingReassembly::check_fragment(PacketHeaderIPv4 &packet) {
    if (packet.ipid() != ipid || !needs_reassembly(packet)) throw std::runtime_error("packet isn't fragmented or wrong ip_id");
}

void IPv4FlowPendingReassembly::add_packet(PacketHeaderIPv4 &packet) {
    check_fragment(packet);
    packets.emplace(packet);
    if (!packet.flag_mf()) have_last = true;
    if (!packet.frag_offset()) have_first = true;
    try_reassemble();
}

std::unique_ptr<PacketBuffer> IPv4FlowPendingReassembly::try_reassemble() {
    if (steady_clock::now() >= expires) throw ipv4_reassembly_timeout();
    if (!have_last || !have_first) return nullptr;
    
    size_t expected_next_offset = 0;
    size_t total_ipv4_content_size = 0;
    for (const auto &p : packets) {
        if (p.offset != expected_next_offset) return nullptr;
        expected_next_offset += p.ipv4_data_len / 8;
        total_ipv4_content_size += p.ipv4_data_len;
    }
    // Allocate a new pb large enough to hold total_ipv4_content_size
    
    auto &ip_header = packets.begin()->ip_header;
    auto new_buf = std::make_unique<PacketBuffer>(total_ipv4_content_size + ip_header.header_size());
    PacketHeaderIPv4 new_ipv4(*new_buf);
    new_ipv4.copy_from(ip_header);
    PacketBufferOffset ip_data_pbo = new_ipv4.next_header_offset();
    size_t data_offset = 0;
    for (const auto &p : packets) {
        ip_data_pbo.copy_from(p.ip_header.next_header_offset(), p.ip_header.data_size(), data_offset);
        data_offset += p.ip_header.data_size();
    }
    return new_buf;
}

//NetworkingIPv4
NetworkingIPv4::NetworkingIPv4(Networking &n) : networking(n) {
    register_callback(typeid(PacketHeaderICMP),
                      [this](NetworkingIPv4 &nv4, PacketHeaderIPv4 &ipv4, void *d) { return icmp_echo_callback(nv4, ipv4, d); }
                     );
}

void NetworkingIPv4::clean() {
    auto now = steady_clock::now();
    for (auto it = pending_reassembly.begin(); it != pending_reassembly.end(); ++it) {
        if (now >= it->second.expires) {
            pending_reassembly.erase(it);
            stats.expired_fragmented++;
        }
    }
}

void NetworkingIPv4::register_callback(const std::type_info &packet_type, const NetworkingIPv4InputCallback &callback, void *data) {
    ipv4_callbacks[packet_type].push_back({callback, data});
}

bool NetworkingIPv4::process_next_header(PacketHeaderIPv4 &packet) {
    decltype(ipv4_callbacks)::const_iterator callbacks;
    switch (packet.protocol()) {
        case IPPROTO::TCP:
            callbacks = ipv4_callbacks.find(typeid(PacketHeaderTCP));
            break;
            
        case IPPROTO::UDP:
            callbacks = ipv4_callbacks.find(typeid(PacketHeaderUDP));
            break;
            
        case IPPROTO::ICMP:
            callbacks = ipv4_callbacks.find(typeid(PacketHeaderICMP));
            break;
            
        default:
            stats.unknown_protocols++;
            return true;
    }
    if (callbacks == ipv4_callbacks.end()) return true;
    for (auto &cb : callbacks->second) {
        cb.func(*this, packet, cb.data);
    }
    return true;
}

bool NetworkingIPv4::process(PacketHeaderIPv4 &packet) {
    if (packet.checksum() % 2) clean(); // We should clean periodically, but we can optimize later.
    if (IPv4FlowPendingReassembly::needs_reassembly(packet)) {
        return possibly_reassemble(packet);
    }
    return process_next_header(packet);
}

bool NetworkingIPv4::possibly_reassemble(PacketHeaderIPv4 &packet) {
    auto pending = pending_reassembly.find(packet.ipid());
    if (pending == pending_reassembly.end()) {
        if (pending_reassembly.size() >= IPV4_REASSEMBLY_MAX_PENDING) {
            stats.over_frag_limit++;
            return true;
        }
        pending_reassembly.insert({packet.ipid(), packet});
        // If it needs reassembly and we only have one packet, don't bother trying to reassemble.
        return true;
    }
    
    pending->second.add_packet(packet);
    try {
        if (auto r = pending->second.try_reassemble()) {
            pending_reassembly.erase(pending);
            PacketHeaderIPv4 assembeled_ipv4(*r);
            return process_next_header(assembeled_ipv4);
        }
    } catch (ipv4_reassembly_timeout) {
        pending_reassembly.erase(pending);
    }
    
    return true;
}

void NetworkingIPv4::send(const IPv4Address &dest, const IPPROTO::IPPROTO proto, PacketBuffer &pb) {
    size_t data_size = pb.size();
    
    routes.get(dest);
    
    pb.unreserve_space(PacketHeaderTCP::minimum_header_size());
    PacketHeaderIPv4 ipv4(pb);
    
    ipv4.build(networking.my_ip, dest, data_size, proto);
    // TODO: Fragment
    
    if (networking.net_driver.is_layer3_interface()) {
        networking.net_driver.send(pb);
    } else {
        networking.eth_layer.send(dest, routes, ETHERTYPE::IP, pb);
    }
}

bool NetworkingIPv4::icmp_echo_callback(NetworkingIPv4 &nv4, PacketHeaderIPv4 &ipv4, void *) {
    if (ipv4.protocol() != IPPROTO::ICMP) return true;
    PacketHeaderICMP incoming_icmp(ipv4.next_header_offset());
    if (incoming_icmp.type() != ICMP::ECHO) return true;
    PacketHeaderICMPEcho incoming_echo(incoming_icmp.next_header_offset());
    auto incoming_echo_data = incoming_echo.next_header_offset();
    
    PacketBuffer pb(PacketHeaderICMP::minimum_header_size() + PacketHeaderICMPEcho::minimum_header_size() + incoming_echo_data.size());
    PacketHeaderICMP new_icmp(pb);
    PacketHeaderICMPEcho new_echo(new_icmp.next_header_offset());
 
    auto outgoing_echo_data = new_echo.next_header_offset();
    
    outgoing_echo_data.copy_from(incoming_echo_data);
    new_echo.seq = incoming_echo.seq();
    new_echo.ident = incoming_echo.ident();
    
    new_icmp.type = ICMP::ECHOREPLY;
    new_icmp.code = 0;
    new_icmp.update_checksum();
    
    nv4.send(ipv4.source(), IPPROTO::ICMP, pb);
    return true;
}
