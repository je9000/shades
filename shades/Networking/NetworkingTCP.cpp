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

TCPSession::TCPSession(NetworkingTCP &n, const NetworkFlowTCP &f) : net_tcp(n), flow(f), state(UNCONFIGURED), last_sent_seq(net_tcp.random_device()()) {
    memset(&stats, 0, sizeof(stats));
    my_window_size = my_max_window_size;
    next_expected_seq = peer_window_size = peer_max_window_size = keepalives_sent = 0;
}

TCPWindowStatus TCPSession::check_packet_in_window(const PacketHeaderTCP &tcp) const {
    if (next_expected_seq == tcp.seq_num()) return NEXT_IN_WINDOW;

    /*
     * To avoid "blind in-window attacks", RFC5961 requires RST packets be
     * exactly the next expected packet, otherwise a "challenge ack" is sent.
    */
    if (tcp.rst()) return RST_OUT_OF_WINDOW;

    uint32_t wrapped_max_window = next_expected_seq + my_window_size;

    // Does the sequence number wrap?
    if (wrapped_max_window < next_expected_seq) {
        if (tcp.seq_num() < next_expected_seq && tcp.seq_num() > wrapped_max_window) return BEFORE_WINDOW;
        if (tcp.seq_num() > next_expected_seq || tcp.seq_num() <= wrapped_max_window) return LATER_IN_WINDOW;
    } else {
        if (next_expected_seq > tcp.seq_num()) return BEFORE_WINDOW;
        if (next_expected_seq + peer_window_size > tcp.seq_num()) return LATER_IN_WINDOW;
    }
    return AFTER_WINDOW;
}

void TCPSession::keepalive() {
    if (keepalives_sent > NETWORKING_TCP_MAX_KEEPALIVES) {
        send_rst();
        state = CLOSED;
    } else {
        send_ack();
    }
}

void TCPSession::send_rst() {
    net_tcp.send_rst(flow, *this);
    state = CLOSED;
}

/*
void TCPSession::send_rst(const PacketHeaderTCP &tcp) {
    net_tcp.send_rst(flow, tcp.seq_num(), this);
    state = CLOSED;
}
 */

void TCPSession::send_ack() {
    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP ack(pb);

    ack.build(flow.local_port, flow.remote_port, ++last_sent_seq);
    ack.ack(true);
    ack.ack_num = next_expected_seq;

    net_tcp.send(flow, ack, this);
}

void TCPSession::send_fin() {
    if (state != ESTABLISHED && state != CLOSE_WAIT) return; // Possible to get here if a user sends multiple fins in their callback, so ignore.
    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP fin(pb);
    
    last_sent_seq++;
    fin.build(flow.local_port, flow.remote_port, last_sent_seq);
    fin.ack(true);
    fin.ack_num = next_expected_seq;
    fin.fin(true);
    
    net_tcp.send(flow, fin, this);
    switch (state) {
        case ESTABLISHED:
            state = FIN_WAIT_1;
            break;
            
        case CLOSE_WAIT:
            state = LAST_ACK;
            break;
            
        default:
            throw std::runtime_error("Invalid state");
    }
}

void TCPSession::run_callback(TCPSessionEvent event, const PacketHeaderTCP &tcp) {
    auto action = callback.func(event, this->flow, this, tcp);
    switch (action) {
        case SESSION_RESET:
            send_rst();
            break;
            
        case SESSION_FIN:
            send_fin();
            break;
            
        default:
            break;
    }
}

void TCPSession::process(const PacketHeaderTCP &tcp) {
    if (state == TIME_WAIT) {
        net_tcp.stats.received_on_time_wait++;
        return; // Socket is done, do nothing.
    }

    if (state == CLOSED) {
        // We shouldn't be receiving events on a closed connection.
        net_tcp.send_rst(flow, *this);
        net_tcp.stats.recevied_on_closed++;
        return;
    }
    
    TCPWindowStatus window_status = check_packet_in_window(tcp);
    switch (window_status) {
        case RST_OUT_OF_WINDOW:
            stats.out_of_window_rst++;
            return;

        case BEFORE_WINDOW:
            stats.duplicate_packets++;
            // signal congestion
            return;

        case AFTER_WINDOW:
            stats.out_of_window++;
            // signal congestion
            return;

        case LATER_IN_WINDOW:
            //TODO packets pending in window
            return;

        case NEXT_IN_WINDOW:
            // all good
            break;
    }
    
    stats.packets_received++;
    stats.bytes_received += tcp.size() - tcp.header_size();
    last_recv_time = NetworkingTCPSteadyClock::now();
    keepalives_sent = 0;

    /*
     * TCP data is limited to 64k so the cast is safe.
     * Note we're not accounting for "holes"/missing packets. TODO
     */
    next_expected_seq = tcp.seq_num() + static_cast<uint32_t>(tcp.data_size());
    if (!tcp.data_size() && tcp.fin()) next_expected_seq++;
    
    if (tcp.rst()) {
        state = CLOSED;
        run_callback(CONNECTION_RESET, tcp);
        return;
    }

    switch (state) {
        case CLOSE_WAIT:
            if (tcp.fin()) {
                state = CLOSED;
                run_callback(CONNECTION_CLOSED, tcp);
            }
            // Ignore anything else.
            return;

        case LAST_ACK:
            if (tcp.ack()) {
                state = CLOSED;
            }
            // Ignore anything else.
            return;

        case SYN_RECEIVED:
            if (!tcp.ack()) return; // Stat here?
            state = ESTABLISHED;
            run_callback(CONNECTED, tcp);
            if (tcp.data_size()) {
                run_callback(DATA, tcp);
                send_ack();
            }
            return;
            
        case ESTABLISHED:
            if (tcp.data_size()) run_callback(DATA, tcp); // We're not tracking/ordering data
            if (tcp.fin()) {
                state = CLOSE_WAIT;
                run_callback(CONNECTION_CLOSING, tcp);
            }
            // If one of the callbacks above sent an RST or FIN, don't ACK here because they did.
            if (state == ESTABLISHED) send_ack();
            return;
            
        default:
            throw std::runtime_error("Invalid state");
    }
}

// NetworkingTCP
NetworkingTCP::NetworkingTCP(NetworkingIPv4 *n) : net4(n) {
    memset(&stats, 0, sizeof(stats));
    if (net4) {
        net4->register_callback(
            typeid(PacketHeaderTCP),
            [this](size_t, void *, NetworkingIPv4 &, PacketHeaderIPv4 &ipv4) { return process(ipv4); }
        );
        net4->get_network().get_input().register_timer_callback(
            [this](size_t, void *, NetworkingInput &, NetworkingInputSteadyClockTime now) { return timer_callback(now); }
        );
    }
}

void NetworkingTCP::timer_callback(NetworkingInputSteadyClockTime now) {
    for(auto it = ipv4_flows.begin(); it != ipv4_flows.end(); ) {
        TCPSession &session = it->second;
        auto time_diff = now - session.last_recv_time;
        if (session.keepalives_sent >= NETWORKING_TCP_MAX_KEEPALIVES) {
            send_rst(it->first, session);
            session.state = CLOSED;
            it = ipv4_flows.erase(it);
        } else if (session.state == CLOSED || (session.state == TIME_WAIT && time_diff >= NETWORKING_TCP_TIMEOUT_TIME_WAIT)) {
            it = ipv4_flows.erase(it);
        } else if (session.state == SYN_RECEIVED && time_diff >= NETWORKING_TCP_TIMEOUT_SYN_RECEIVED) {
            // TODO retry syn-ack
            session.keepalives_sent++;
            session.last_recv_time = now; // Reset the keepalive timer. Separate timers for that?
        } else {
            ++it;
        }
    }
}

void NetworkingTCP::send(const NetworkFlowTCP &flow, PacketHeaderTCP &tcp, TCPSession *session) {
    auto &pb = tcp.backing_buffer();
    if (session) {
        session->stats.packets_sent++;
        session->stats.bytes_sent += pb.size();
    }
    if (flow.ip_ver() == PROTO_IPv4) {
        auto flow4 = dynamic_cast<const NetworkFlowIPv4TCP &>(flow);
        tcp.update_checksum(flow4.local_ip, flow4.remote_ip);
        net4->send(flow4.remote_ip, IPPROTO::TCP, pb);
    } // TODO ipv6
}

/*
 * Per RFC 793, there are 3 kinds of resets we send:
 * 1) Resetting an existing connection. In this case, pass the TCPSession object
 *    and we will set the ACK flag and set the ACK number to the next expected
 *    offset.
 * 2) Resetting an incoming ACK.
 * 3) ???
 */
void NetworkingTCP::send_rst(const NetworkFlowTCP &flow, PacketHeaderTCP &tcp) {
    uint32_t seq = 0;
    if (tcp.ack()) {
        seq = tcp.ack_num();
    }

    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP rst(pb);

    rst.build(flow.local_port, flow.remote_port, seq);
    rst.rst(true);
    if (!tcp.ack()) {
        rst.ack(true);
        // Again, the cast is safe beacuse data_size is capped at 65k.
        rst.ack_num = tcp.seq_num() + static_cast<uint32_t>(tcp.data_size());
    }

    send(flow, rst, nullptr);
}

void NetworkingTCP::send_rst(const NetworkFlowTCP &flow, TCPSession &session) {
    uint32_t seq;

    seq = ++session.last_sent_seq;
    session.stats.packets_sent++;

    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP rst(pb);

    rst.build(flow.local_port, flow.remote_port, seq);
    rst.rst(true);
    rst.ack(true);
    rst.ack_num = session.next_expected_seq;
    
    send(flow, rst, &session);
}

TCPSession NetworkingTCP::send_accept(const NetworkFlowTCP &flow, const PacketHeaderTCP &tcp, const NetworkFlowTCPCallbackInfo cb) {
    TCPSession session(*this, flow);
    session.state = SYN_RECEIVED;
    session.next_expected_seq = tcp.seq_num() + 1;
    session.stats.packets_sent++;
    session.callback = cb;
    session.peer_window_size = session.peer_max_window_size = session.congestion_window = tcp.window_size(); // Scaling options TODO
    if (session.congestion_window > NETWORKING_TCP_MAX_INITIAL_CONGESTION_WINDOW) session.congestion_window = NETWORKING_TCP_MAX_INITIAL_CONGESTION_WINDOW;
    
    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP syn_ack(pb);
    
    syn_ack.build(flow.local_port, flow.remote_port, session.last_sent_seq);
    syn_ack.ack(true);
    syn_ack.ack_num = session.next_expected_seq;
    syn_ack.syn(true);
    
    send(flow, syn_ack, &session);
    return session;
}

void NetworkingTCP::process(PacketHeaderIPv4 &ipv4) {
    //if (ipv4.source() == net4.get_network().my_ip) return; // Don't process outgoing packets.
    if (ipv4.dest() != net4->get_network().my_ip) return; // Make sure this is destined for me. An additional promiscuous check I suppose.
    
    PacketHeaderTCP tcp(ipv4.next_header_offset());
    tcp.check(ipv4.source(), ipv4.dest());
    
    NetworkFlowIPv4TCP this_flow(ipv4.source(), tcp.source_port(), ipv4.dest(), tcp.dest_port());
    auto found = ipv4_flows.find(this_flow);
    
    if (found == ipv4_flows.end()) {
        // Silently drop inbound resets if no one is listening.
        if (tcp.rst()) {
            stats.unmatched_rst++;
            return;
        }
        
        // Reset anything else unless it's a SYN
        if (!TCPSession::is_handshake_syn(tcp)) {
            stats.unmatched_session++;
            send_rst(this_flow, tcp);
            return;
        }
        
        // Is anyone listening? If they are, do they want to accept this connection?
        auto listener = ipv4_listening_ports.find(tcp.dest_port());
        if (listener == ipv4_listening_ports.end()) {
            stats.syn_to_closed_port++;
            send_rst(this_flow, tcp);
            return;
        }
        if (listener->second.func && listener->second.func(INCOMING_CONNECTION, this_flow, nullptr, tcp) != SESSION_OK) {
            send_rst(this_flow, tcp);
            return;
        }
        ipv4_flows.emplace(this_flow, send_accept(this_flow, tcp, {listener->second.func}));
    } else {
        found->second.process(tcp);
    }
}

// TODO handle TCP_IP_VERSION v6
void NetworkingTCP::register_listener(const TCP_IP_VERSION ip_ver, const uint_fast16_t port, const NetworkFlowTCPCallback &callback) {
    ipv4_listening_ports.emplace(port, callback);
}

void NetworkingTCP::unregister_listener(const TCP_IP_VERSION ip_ver, const uint_fast16_t port) {
    ipv4_listening_ports.erase(port);
}
