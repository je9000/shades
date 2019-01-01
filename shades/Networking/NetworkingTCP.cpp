#include "Networking.hpp"
#include "NetworkingIPv4.hpp"
#include "NetworkingTCP.hpp"

#include <random>
#include <thread>

bool NetworkFlowIPv4TCP::operator==(const NetworkFlowIPv4TCP &other) const {
    return (
        remote_ip == other.remote_ip &&
        local_ip == other.local_ip &&
        local_port == other.local_port &&
        remote_port == other.remote_port
    );
}

// TCP Session

TCPSession::TCPSession(NetworkingTCP &n, NetworkFlowTCPCallback &cb) :
        net_tcp(n), flow(nullptr), next_seq_to_send(net_tcp.random_device()())
    {
    memset(&stats, 0, sizeof(stats));
    my_window_size = my_max_window_size;
    next_expected_seq = last_received_ack = last_sent_ack = 0;
    peer_window_size = 0;
    keepalives_sent = 0;
    callback.func = cb;
    //std::clog << "TCPSession " << flow.ip_ver() << "\n";
}

void TCPSession::set_flow(const NetworkFlowTCP &f) {
    flow = &f;
}

TCPSession::~TCPSession() {
    //std::clog << "~TCPSession\n";
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

void TCPSession::send_data(std::string &s) {
    send_data(s.data(), s.size());
}

void TCPSession::send_data(const char *data, size_t len) {
    PacketBuffer pb(PacketHeaderTCP::minimum_header_size() + len);
    PacketHeaderTCP sendme(pb);

    sendme.build(flow->local_port, flow->remote_port, next_seq_to_send);
    sendme.psh(true);
    sendme.ack(true);
    sendme.ack_num = next_expected_seq;
    last_sent_ack = next_expected_seq;

    auto data_offset = sendme.next_header_offset();
    data_offset.copy_from(reinterpret_cast<const unsigned char *>(data), len);

    // send will append IP and ethernet headers, so store a copy before send()
    unacked.emplace(next_seq_to_send, sendme);
    send(sendme);
    next_seq_to_send += len;
}

void TCPSession::send(PacketHeaderTCP &tcp) {
    if (peer_window_size == 0 || (unacked.size() > NETWORKING_TCP_MAX_INITIAL_CONGESTION_WINDOW)) {
        /*
         * Since we're not asynchronous we can't hold this data until we get a
         * window update, probe with a persist timer, or do real congestion
         * delays. Instead lets just wait a bit and then try and send, and if
         * the peer doesn't ack it we will retransmit later. Hopefully this is
         * slow enough.
         *
         * It's messy to sleep the thread, but it's less messy than finding a
         * way to block the caller while we schedule this write for later.
         *
         * A fixed timeout is not good congestion control.
         */
        std::this_thread::sleep_for(NETWORKING_TCP_CONGESTION_SEND_DELAY * unacked.count());
    }
    net_tcp.send(*flow, tcp, this);
}

void TCPSession::send_rst() {
    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP rst(pb);

    rst.build(flow->local_port, flow->remote_port, next_seq_to_send);
    rst.rst(true);
    rst.ack(true);
    rst.ack_num = next_expected_seq;
    last_sent_ack = next_expected_seq;

    send(rst);
    state = CLOSED;
}

void TCPSession::send_ack() {
    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP ack(pb);

    ack.build(flow->local_port, flow->remote_port, next_seq_to_send);
    ack.ack(true);
    ack.ack_num = next_expected_seq;
    last_sent_ack = next_expected_seq;

    send(ack);
}

void TCPSession::send_keepalive_ack() {
    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP ack(pb);

    ack.build(flow->local_port, flow->remote_port, last_received_ack - 1);
    ack.ack(true);
    ack.ack_num = next_expected_seq;
    // Don't change last_sent_ack because we're not ACKing new data.

    send(ack);
}

void TCPSession::send_fin() {
    if (state != ESTABLISHED && state != CLOSE_WAIT) return; // Possible to get here if a user sends multiple fins in their callback, so ignore.
    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP fin(pb);

    fin.build(flow->local_port, flow->remote_port, next_seq_to_send);
    fin.fin(true);
    fin.ack(true);
    fin.ack_num = next_expected_seq;
    last_sent_ack = next_expected_seq;
    
    send(fin);
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
    unacked.emplace(next_seq_to_send, fin);
    next_seq_to_send++;
}

void TCPSession::send_accept(const PacketHeaderTCP &tcp) {
    state = SYN_RECEIVED;
    next_expected_seq = tcp.seq_num() + 1;
    stats.packets_sent++;
    last_recv_time = NetworkingTCPSteadyClock::now();
    peer_window_size = congestion_window = tcp.window_size(); // Scaling options TODO
    if (congestion_window > NETWORKING_TCP_MAX_INITIAL_CONGESTION_WINDOW) congestion_window = NETWORKING_TCP_MAX_INITIAL_CONGESTION_WINDOW;

    PacketBuffer pb(PacketHeaderTCP::minimum_header_size());
    PacketHeaderTCP syn_ack(pb);

    syn_ack.build(flow->local_port, flow->remote_port, next_seq_to_send++);
    syn_ack.syn(true);
    syn_ack.ack(true);
    syn_ack.ack_num = next_expected_seq;
    last_sent_ack = next_expected_seq;

    send(syn_ack);
    /*
     * Not going to register this as unacked. We can rely on them to resend
     * their initial SYN if they want this connection to happen.
     */
}

unsigned int TCPSession::run_callback(TCPSessionEvent event, const PacketHeaderTCP &tcp) {
    auto action = callback.func(event, *flow, this, tcp);
    switch (action) {
        case SESSION_RESET:
            return NETWORKING_TCP_CALLBACK_WANT_RST;
            
        case SESSION_FIN:
            return NETWORKING_TCP_CALLBACK_WANT_FIN;
            
        default:
            return NETWORKING_TCP_CALLBACK_OK;
    }
}

bool TCPSession::ack_is_valid(uint32_t unacked_seq, uint32_t ack) {
    if (next_seq_to_send >= unacked_seq) {
        // Sequence numbers haven't wrapped
        if (unacked_seq <= ack && ack <= next_seq_to_send) return true;
    } else {
        // Sequence numbers have wrapped.
        if (ack <= next_seq_to_send || ack >= unacked_seq) return true;
    }

    return false;
}

void TCPSession::process_ack(uint32_t ack) {
    // Doesn't handle partially acknowledged packets. TODO
    // Needs to be tested. TODO

    uint32_t acked_byte = ack - 1;

    for(auto it = unacked.begin(); it != unacked.end();) {
        uint32_t unacked_seq = it->first + it->second.data_size;
        if (ack_is_valid(unacked_seq, acked_byte)) {
            it = unacked.erase(it);
        } else if (unacked_seq > acked_byte) {
            break;
        } else {
            ++it;
        }
    }
}

/*
 * Note, we totally ignore both the PSH and URG flags. We deliver all data in
 * order to the callback. URG isn't well specified and is rarely used, so we
 * can implement support when we find a use case.
 */
void TCPSession::process(const PacketHeaderTCP &tcp) {
    unsigned int callback_op;

    if (state == TIME_WAIT) {
        net_tcp.stats.received_on_time_wait++;
        return; // Socket is done, do nothing.
    }

    if (state == CLOSED) {
        // We shouldn't be receiving events on a closed connection.
        net_tcp.send_rst(*flow, tcp);
        net_tcp.stats.recevied_on_closed++;
        return;
    }
    
    TCPWindowStatus window_status = check_packet_in_window(tcp);
    switch (window_status) {
        case RST_OUT_OF_WINDOW:
            stats.out_of_window_rst++;
            send_ack(); // Challenge ACK.
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
            if (tcp.ack()) {
                // An ack from the future!
                if (tcp.ack() + tcp.data_size() >= next_seq_to_send) {
                    send_rst();
                    return;
                }
                process_ack(tcp.ack_num());
                last_received_ack = tcp.ack_num();
            }
            if (tcp.flags() != TCP_FLAG_ACK) { // More than just an empty ACK.
                received_out_of_order.emplace(tcp.seq_num(), tcp);
            }
            return;

        case NEXT_IN_WINDOW:
            // all good
            break;
    }
    
    stats.packets_received++;
    stats.bytes_received += tcp.size() - tcp.header_size();
    last_recv_time = NetworkingTCPSteadyClock::now();
    keepalives_sent = 0;

    // TCP data is limited to 64k so the cast is safe.
    next_expected_seq += static_cast<uint32_t>(tcp.data_size());
    if (!tcp.data_size() && tcp.fin()) next_expected_seq++;

    // See comments in send for how we handle zero windows.
    peer_window_size = tcp.window_size();
    
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
            if (tcp.ack()) last_received_ack = tcp.ack_num();
            // Ignore anything else.
            return;

        case LAST_ACK:
            if (tcp.ack()) {
                last_received_ack = tcp.ack_num();
                state = CLOSED;
            }
            // Ignore anything else.
            return;

        case SYN_RECEIVED:
            if (!tcp.ack() || tcp.fin()) {
                send_rst(); // Unexpected! Abort.
                return;
            }
            if (tcp.syn()) { // retransmit of the initial syn packet
                send_accept(tcp);
                return;
            }
            state = ESTABLISHED;
            net_tcp.listen_port_connected(*flow);
            last_received_ack = tcp.ack_num();
            callback_op = run_callback(CONNECTED, tcp);
            if (callback_op & NETWORKING_TCP_CALLBACK_WANT_RST) {
                send_rst();
                return;
            }

            // Early data
            if (tcp.data_size()) callback_op |= run_callback(DATA, tcp);

            if (callback_op & NETWORKING_TCP_CALLBACK_WANT_RST) {
                send_rst();
            } else if (callback_op & NETWORKING_TCP_CALLBACK_WANT_FIN) {
                send_fin();
            } else if (tcp.data_size() && last_sent_ack < tcp.seq_num() + tcp.data_size()) {
                send_ack();
            }
            return;
            
        case ESTABLISHED:
            if (!tcp.ack()) {
                /*
                 * Per RFC 793:
                 * Once a connection is established this is always sent.
                 * We could probably RST here, but Linux just ignores the packet
                 * so let's try that.
                 */
                return;
            }
            callback_op = NETWORKING_TCP_CALLBACK_OK;
            process_ack(last_received_ack);
            last_received_ack = tcp.ack_num();

            if (tcp.data_size()) {
                callback_op |= run_callback(DATA, tcp);
            }

            if (tcp.fin()) {
                state = CLOSE_WAIT;
                callback_op |= run_callback(CONNECTION_CLOSING, tcp);
            }

            if (callback_op & NETWORKING_TCP_CALLBACK_WANT_RST) {
                next_expected_seq += tcp.data_size();
                send_rst();
                return;
            }

            // Data after a FIN? Ignore it.
            if (!tcp.fin()) {
                // safe cast, data_size is limited to 64k
                uint32_t ooo_target_seq = tcp.seq_num() + static_cast<uint32_t>(tcp.data_size());

                /*
                 * If we return from here after a rst or fin, we will eventually
                 * clean out all of received_out_of_order when the connection is
                 * torn down.
                 */
                auto found = received_out_of_order.find(ooo_target_seq);
                while (found != received_out_of_order.end()) {
                    PacketHeaderTCP old_tcp(found->second.pb); // Already checked.
                    if (old_tcp.data_size()) callback_op |= run_callback(DATA, old_tcp);
                    next_expected_seq += tcp.data_size();

                    if (callback_op & NETWORKING_TCP_CALLBACK_WANT_RST) {
                        send_rst();
                        return;
                    }

                    if (old_tcp.fin()) {
                        next_expected_seq++;
                        state = CLOSE_WAIT;
                        callback_op |= run_callback(CONNECTION_CLOSING, old_tcp);
                        if (callback_op & NETWORKING_TCP_CALLBACK_WANT_RST) {
                            send_rst();
                            return;
                        }
                        break;
                    }

                    ooo_target_seq += old_tcp.data_size();
                    received_out_of_order.erase(found);
                    found = received_out_of_order.find(ooo_target_seq);
                }
            }

            if (callback_op & NETWORKING_TCP_CALLBACK_WANT_FIN) {
                send_fin();
            } else if ((tcp.data_size() || tcp.fin()) && last_sent_ack < tcp.seq_num() + tcp.data_size()) {
                send_ack();
            }
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
        if (session.state == CLOSED) {
            it = ipv4_flows.erase(it);
        } else if (time_diff >= NETWORKING_TCP_IDLE_TIMEOUT && now - session.last_keepalive_time >= NETWORKING_TCP_TIME_BETWEEN_KEEPALIVES) {
            if (session.keepalives_sent >= NETWORKING_TCP_MAX_KEEPALIVES) {
                session.send_rst();
                it = ipv4_flows.erase(it);
            } else {
                session.send_keepalive_ack();
                session.keepalives_sent++;
                session.last_keepalive_time = now;
                ++it;
            }
        } else if (   (session.state == TIME_WAIT    && time_diff >= NETWORKING_TCP_TIMEOUT_TIME_WAIT)
                   || (session.state == SYN_RECEIVED && time_diff >= NETWORKING_TCP_TIMEOUT_SYN_RECEIVED)
                  ) {
            session.state = CLOSED;
            if (session.state == SYN_RECEIVED) listen_port_aborted(*session.flow);
            it = ipv4_flows.erase(it);
        } else {
            for(auto &pending : session.unacked) {
                // This is not good congestion control.
                if (now - pending.second.ts > NETWORKING_TCP_RETRANSMIT_TIMEOUT) {
                    PacketBuffer pb(pending.second.pb);
                    PacketHeaderTCP tcp(pb);
                    session.send(tcp);
                    pending.second.ts = now;
                }
            }
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
        const NetworkFlowIPv4TCP &flow4 = dynamic_cast<const NetworkFlowIPv4TCP &>(flow);
        tcp.update_checksum(flow4.local_ip, flow4.remote_ip);
        net4->send(flow4.remote_ip, IPPROTO::TCP, pb);
    } // TODO ipv6
}

/*
 * Per RFC 793, there are 3 kinds of resets we send:
 * 1) Resetting an existing connection. In this case, pass the TCPSession object
 *    and we will set the ACK flag and set the ACK number to the next expected
 *    offset.
 * 2) Resetting an incoming ACK. To do this we set our sequence number to the
 *    ACK number.
 * 3) Resetting any other incoming packet. In this case we use a sequence number
 *    of zero and actually ACK the data.
 */
void NetworkingTCP::send_rst(const NetworkFlowTCP &flow, const PacketHeaderTCP &tcp) {
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

void NetworkingTCP::process(PacketHeaderIPv4 &ipv4) {
    //if (ipv4.source() == net4.get_network().my_ip) return; // Don't process outgoing packets.
    if (net4->get_network().my_ip && ipv4.dest() != net4->get_network().my_ip) return; // Make sure this is destined for me. An additional promiscuous check I suppose.
    
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
        if (listener->second.outstanding_syn_ack > NETWORKING_TCP_LISTEN_QUEUE_SIZE) {
            stats.listen_queue_overflow++;
            send_rst(this_flow, tcp);
            return;
        } else if (listener->second.func(INCOMING_CONNECTION, this_flow, nullptr, tcp) != SESSION_OK) {
            send_rst(this_flow, tcp);
            return;
        }
        listener->second.outstanding_syn_ack++;
        /*
         * Since we want the session to be able to access its assoicated flow,
         * we have to assign the flow after the session is created. It's not
         * usable until it has a flow assigned.
         */
        auto new_flow = ipv4_flows.emplace(std::piecewise_construct,
                                           std::forward_as_tuple(this_flow),
                                           std::forward_as_tuple(*this, listener->second.func)
                                           );
        new_flow.first->second.set_flow(new_flow.first->first);
        new_flow.first->second.send_accept(tcp);
    } else {
        found->second.process(tcp);
    }
}

void NetworkingTCP::listen_port_connected(const NetworkFlowTCP &flow) {
    if (flow.ip_ver() == 4) {
        auto found = ipv4_listening_ports.find(flow.local_port);
        if (found != ipv4_listening_ports.end()) found->second.outstanding_syn_ack--;
    } else {
        //IPv6
    }
}

void NetworkingTCP::listen_port_aborted(const NetworkFlowTCP &flow) {
    listen_port_connected(flow);
}

// TODO handle TCP_IP_VERSION v6
void NetworkingTCP::register_listener(const TCP_IP_VERSION ip_ver, const uint_fast16_t port, const NetworkFlowTCPCallback &callback) {
    ipv4_listening_ports.emplace(port, callback);
}

void NetworkingTCP::unregister_listener(const TCP_IP_VERSION ip_ver, const uint_fast16_t port) {
    ipv4_listening_ports.erase(port);
}
