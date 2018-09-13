#include "Networking.hpp"
#include "NetworkingIPv4.hpp"
#include "NetworkingTCP.hpp"

#include <random>

bool NetworkFlowIPv4TCP::operator==(const NetworkFlowIPv4TCP &other) const {
    return (
        remote_ip == other.remote_ip &&
        local_ip == other.local_ip &&
        local_port == other.local_port &&
        remote_port == other.remote_port
    );
}

// TCP Session

TCPSession::TCPSession(NetworkingTCP &n) : net_tcp(n) {}

void TCPSession::accept(const NetworkFlowIPv4TCP &flow, const PacketHeaderTCP &tcp) {
    if (!is_handshake_1(tcp)) return;
    initial_seq = last_sent_seq = net_tcp.random_device()();
    
    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP syn_ack(pb);
    
    syn_ack.build(flow.remote_ip, flow.local_port, initial_seq);
    syn_ack.ack(true);
    syn_ack.ack_num = tcp.seq_num() + 1;
    syn_ack.update_checksum(flow.local_ip, flow.remote_ip);
    
    net_tcp.send(flow, pb);
}

void TCPSession::process(const NetworkFlowIPv4TCP &, const PacketHeaderTCP &tcp) {
    // TODO
}

// NetworkingTCP
NetworkingTCP::NetworkingTCP(NetworkingIPv4 &n) : net4(n) {
    net4.register_callback(
        typeid(PacketHeaderTCP),
        [this](size_t, void *, NetworkingIPv4 &, PacketHeaderIPv4 &ipv4) { return process(ipv4); }
    );
}

void NetworkingTCP::send(const NetworkFlowIPv4TCP &flow, PacketBuffer &pb) {
    net4.send(flow.remote_ip, IPPROTO::TCP, pb);
}

void NetworkingTCP::send_rst(const NetworkFlowIPv4TCP &flow, const PacketHeaderTCP &respond_to) {
    uint32_t seq = 0x52535421; // We don't need an actual random sequence because this session is over.

    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP rst(pb);

    rst.build(flow.local_port, flow.remote_port, seq);
    rst.ack(true);
    rst.rst(true);
    rst.ack_num = respond_to.seq_num() + 1;
    rst.update_checksum(flow.local_ip, flow.remote_ip);
    
    net4.send(flow.remote_ip, IPPROTO::TCP, pb);
}

void NetworkingTCP::process(PacketHeaderIPv4 &ipv4) {
    //if (ipv4.source() == net4.get_network().my_ip) return; // Don't process outgoing packets.
    if (ipv4.dest() != net4.get_network().my_ip) return; // Make sure this is destined for me. An additional promiscuous check I suppose.
    
    PacketHeaderTCP tcp(ipv4.next_header_offset());
    tcp.check(ipv4.source(), ipv4.dest());
    
    NetworkFlowIPv4TCP this_flow(ipv4.source(), tcp.source_port(), ipv4.dest(), tcp.dest_port());
    auto found = ipv4_flows.find(this_flow);
    
    if (found == ipv4_flows.end()) {
        if (!TCPSession::is_handshake_1(tcp)) {
            stats.unmatched_session++;
            send_rst(this_flow, tcp);
            return;
        }
        auto listener = listening_ports.find(tcp.dest_port());
        if (listener == listening_ports.end() || (listener->second.func && !listener->second.func(listener->second.data, this_flow, tcp))) {
            send_rst(this_flow, tcp);
            return;
        }
        TCPSession session(*this);
        session.accept(this_flow, tcp);
        ipv4_flows.emplace(this_flow, session);
    } else {
        found->second.process(found->first, tcp);
    }
}

void NetworkingTCP::register_listener(const uint16_t port, NetworkFlowIPv4TCPCallback &callback, void *data) {
    listening_ports[port] = { callback, data };
}

void NetworkingTCP::unregister_listener(const uint16_t port) {
    listening_ports.erase(port);
}
