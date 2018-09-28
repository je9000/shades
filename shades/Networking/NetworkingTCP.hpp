#ifndef NetworkingTCP_h
#define NetworkingTCP_h

#include "PacketHeaderIPv4.hpp"
#include "PacketHeaderTCP.hpp"

#include <string_view>
#include <cstdint>
#include <map>
#include <unordered_map>
#include <chrono>

#define DEBUG_TCP_STATE_TRANSITIONS

using NetworkingTCPSteadyClock = std::chrono::steady_clock;
using NetworkingTCPSteadyClockTime = std::chrono::time_point<NetworkingIPv4SteadyClock>;

// ALl of these are arbitrary unless otherwise specified.
const std::chrono::seconds NETWORKING_TCP_TIMEOUT_TIME_WAIT(60);
const std::chrono::seconds NETWORKING_TCP_TIMEOUT_SYN_RECEIVED(60);
const std::chrono::seconds NETWORKING_TCP_IDLE_TIMEOUT(10); // Per RFC
const std::chrono::seconds NETWORKING_TCP_TIME_BETWEEN_KEEPALIVES(10);
const int NETWORKING_TCP_MAX_KEEPALIVES = 3;
const int NETWORKING_TCP_MINIMUM_WINDOW_SIZE = 8;
const int NETWORKING_TCP_MAX_INITIAL_CONGESTION_WINDOW = 1480 * 10;
const int NETWORKING_TCP_LISTEN_QUEUE_SIZE = 100;

const unsigned int NETWORKING_TCP_CALLBACK_OK = 0;
const unsigned int NETWORKING_TCP_CALLBACK_WANT_FIN = 2;
const unsigned int NETWORKING_TCP_CALLBACK_WANT_RST = 4;

enum TCP_IP_VERSION {
    PROTO_IPv4 = 4,
    PROTO_IPv6 = 6,
};

enum TCPConnectionStates {
    UNCONFIGURED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    CLOSED
};

inline std::ostream& operator<<(std::ostream &os, const TCPConnectionStates &state) {
    switch (state) {
        case UNCONFIGURED:
            os << "UNCONFIGURED";
            break;
        case LISTEN:
            os << "LISTEN";
            break;
        case SYN_SENT:
            os << "SYN_SENT";
            break;
        case SYN_RECEIVED:
            os << "SYN_RECEIVED";
            break;
        case ESTABLISHED:
            os << "ESTABLISHED";
            break;
        case FIN_WAIT_1:
            os << "FIN_WAIT_1";
            break;
        case FIN_WAIT_2:
            os << "FIN_WAIT_2";
            break;
        case CLOSE_WAIT:
            os << "CLOSE_WAIT";
            break;
        case CLOSING:
            os << "CLOSING";
            break;
        case LAST_ACK:
            os << "LAST_ACK";
            break;
        case TIME_WAIT:
            os << "TIME_WAIT";
            break;
        case CLOSED:
            os << "CLOSED";
            break;
        default:
            os << "UNKNOWN";
            break;
    }
    return os;
}

class TCPConnectionState {
private:
    TCPConnectionStates current_state;
#ifdef DEBUG_TCP_STATE_TRANSITIONS
    NetworkingTCPSteadyClockTime state_change_time;
#endif
public:
    TCPConnectionState() : current_state(UNCONFIGURED) {}
    TCPConnectionState(const TCPConnectionStates new_state) : current_state(new_state) {}
    TCPConnectionStates operator=(const TCPConnectionStates new_state) {
#ifdef DEBUG_TCP_STATE_TRANSITIONS
        std::clog << "TCP state transitioning from " << current_state << " to " << new_state << "\n";
        state_change_time = NetworkingTCPSteadyClock::now();
#endif
        current_state = new_state;
        return current_state;
    }
    operator int() const { return current_state; }
    TCPConnectionStates get() const { return current_state; }
};

inline std::ostream& operator<<(std::ostream &os, const TCPConnectionState &state) {
    return os << state.get();
}

enum TCPSessionEvent {
    INCOMING_CONNECTION,
    CONNECTED,
    CONNECTION_RESET,
    CONNECTION_CLOSING,
    CONNECTION_CLOSED,
    DATA,
};

inline std::ostream& operator<<(std::ostream &os, const TCPSessionEvent &event) {
    switch (event) {
        case INCOMING_CONNECTION:
            os << "INCOMING_CONNECTION";
            break;
        case CONNECTED:
            os << "CONNECTED";
            break;
        case CONNECTION_RESET:
            os << "CONNECTION_RESET";
            break;
        case CONNECTION_CLOSING:
            os << "CONNECTION_CLOSING";
            break;
        case CONNECTION_CLOSED:
            os << "CONNECTION_CLOSED";
            break;
        case DATA:
            os << "DATA";
            break;
        default:
            os << "UNKNOWN";
            break;
    }
    return os;
}

enum TCPSessionAction {
    SESSION_OK,
    SESSION_RESET,
    SESSION_FIN
};

enum TCPWindowStatus {
    NEXT_IN_WINDOW,
    LATER_IN_WINDOW,
    AFTER_WINDOW,
    BEFORE_WINDOW,
    RST_OUT_OF_WINDOW
};

class NetworkFlowTCP;
class TCPSession;
typedef std::function<TCPSessionAction(TCPSessionEvent, const NetworkFlowTCP &, const TCPSession *, const PacketHeaderTCP &)> NetworkFlowTCPCallback;
class NetworkFlowTCPCallbackInfo {
public:
    NetworkFlowTCPCallback func;
};

class NetworkFlowTCPListenerCallbackInfo {
public:
    NetworkFlowTCPCallback func;
    unsigned int outstanding_syn_ack;
    struct {
        size_t incoming_connections;
    } stats;
    NetworkFlowTCPListenerCallbackInfo(const NetworkFlowTCPCallback &f) : func(f) {
        outstanding_syn_ack = 0;
        memset(&stats, 0, sizeof(stats));
    }
};

class TCPInflightData {
public:
    uint32_t seq, data_size;
    NetworkingTCPSteadyClockTime ts;
    PacketBuffer pb;
    TCPInflightData(const PacketHeaderTCP &tcp) :
        seq(tcp.seq_num()),
        data_size(static_cast<uint32_t>(tcp.data_size())), // Again, limited to 64k
        ts(NetworkingTCPSteadyClock::now()),
        pb(tcp.header_offset())
    {}
    TCPInflightData(const TCPInflightData &) = delete;
};

typedef std::map<uint_fast32_t, TCPInflightData> TCPInflightDataOrderedBySeq;

class NetworkingTCP;
class TCPSession {
private:
    friend NetworkingTCP;
    struct {
        size_t packets_sent, packets_received, bytes_sent, bytes_received,
               out_of_window, out_of_window_rst, duplicate_packets;
    } stats;
public:
    NetworkingTCP &net_tcp;
    const NetworkFlowTCP *flow;
    NetworkFlowTCPCallbackInfo callback;

    TCPConnectionState state;
    NetworkingTCPSteadyClockTime last_recv_time;

    uint32_t next_seq_to_send, next_expected_seq, last_received_ack;
    uint_fast32_t peer_window_size, peer_max_window_size, congestion_window; // RWND and CWND

    uint_fast32_t my_window_size;
    const uint_fast32_t my_max_window_size = TCP_DEFAULT_WINDOW_SIZE;
    
    uint_fast8_t keepalives_sent;
    NetworkingTCPSteadyClockTime last_keepalive_time;

    TCPInflightDataOrderedBySeq unacked;
    TCPInflightDataOrderedBySeq received_out_of_order;

    TCPSession(NetworkingTCP &, NetworkFlowTCPCallback &);
    TCPSession(const TCPSession &) = delete;
    TCPSession(TCPSession &&) = delete;
    ~TCPSession();
    void set_flow(const NetworkFlowTCP &);

    void process(const PacketHeaderTCP &);
    unsigned int run_callback(TCPSessionEvent, const PacketHeaderTCP &);
    TCPWindowStatus check_packet_in_window(const PacketHeaderTCP &) const;
    void free_acked(uint32_t);

    void send(PacketHeaderTCP &);
    void send_rst();
    void send_ack();
    void send_keepalive_ack();
    void send_fin();
    void send_accept(const PacketHeaderTCP &);
    void send_data(std::string_view);
    void send_data(const char *, size_t);
    
    static bool is_handshake_syn(const PacketHeaderTCP &tcp) {
        // The first part of the handshake has to be a SYN packet with no other flags set.
        return (tcp.syn() && !tcp.ack() && !tcp.fin() && !tcp.psh() && !tcp.rst() && tcp.window_size() >= NETWORKING_TCP_MINIMUM_WINDOW_SIZE);
    }
    
    static bool is_handshake_synack(const PacketHeaderTCP &tcp) {
        return (tcp.syn() && tcp.ack() && !tcp.fin() && !tcp.psh() && !tcp.rst());
    }
};

class NetworkFlowTCP {
public:
    const uint_fast16_t remote_port, local_port;

    NetworkFlowTCP(const uint_fast16_t lport, const uint_fast16_t rport) :
        local_port(lport),
        remote_port(rport)
    {}
    
    virtual ~NetworkFlowTCP() {};
    virtual TCP_IP_VERSION ip_ver() const = 0;
};

class NetworkFlowIPv4TCP : public NetworkFlowTCP {
public:
    const IPv4Address remote_ip, local_ip;

    NetworkFlowIPv4TCP(const IPv4Address rip, uint_fast16_t rport, const IPv4Address lip, uint_fast16_t lport) :
        NetworkFlowTCP(lport, rport),
        remote_ip(rip),
        local_ip(lip)
    {}

    inline TCP_IP_VERSION ip_ver() const { return PROTO_IPv4; }
    bool operator==(const NetworkFlowIPv4TCP &other) const;
};

namespace std {
    template <>
    struct hash<const NetworkFlowIPv4TCP> {
        inline std::size_t operator()(const NetworkFlowIPv4TCP &nf4t) const {
            if (sizeof(std::size_t) >= 8) {
                return ((static_cast<std::size_t>(nf4t.local_ip.ip_int) ^ nf4t.remote_ip.ip_int) << 32) | (nf4t.local_port << 16) | nf4t.remote_port;
            } else {
                return nf4t.local_ip.ip_int ^ nf4t.remote_ip.ip_int ^ nf4t.local_port ^ nf4t.remote_port;
            }
        }
    };
}

class NetworkingIPv4;
class NetworkingTCP {
private:
    NetworkingIPv4 *net4;
    //NetworkingIPv6 *net6;
    std::random_device rd;
    
    std::unordered_map<uint16_t, NetworkFlowTCPListenerCallbackInfo> ipv4_listening_ports;
    std::unordered_map<const NetworkFlowIPv4TCP, TCPSession> ipv4_flows;
private:
    friend TCPSession;
    struct {
        size_t unmatched_session, recevied_out_of_window, recevied_on_closed,
               syn_to_closed_port, unmatched_rst, received_on_time_wait,
               listen_queue_overflow;
    } stats;
public:
    NetworkingTCP(NetworkingIPv4 *n);
    NetworkingTCP(const NetworkingTCP &) = delete;
    NetworkingTCP(NetworkingTCP &&) = delete;

    std::random_device &random_device() { return rd; }
    void process(PacketHeaderIPv4 &);
    void timer_callback(NetworkingInputSteadyClockTime);

    /*
     * Used to track the outstanding SYN+ACKs for a socket. That's done to
     * avoid allocating too many sessions for outstanding connection attempts.
     * We could iterate through all open sessions and count, but this should be
     * faster. If the code ends up too complicated it can be changed.
     */
    void listen_port_connected(const NetworkFlowTCP &);
    void listen_port_aborted(const NetworkFlowTCP &);
    
    void register_listener(const TCP_IP_VERSION, const uint_fast16_t, const NetworkFlowTCPCallback &);
    void unregister_listener(const TCP_IP_VERSION, const uint_fast16_t);
    
    void send_rst(const NetworkFlowTCP &, TCPSession &);
    void send_rst(const NetworkFlowTCP &, PacketHeaderTCP &);
    void send(const NetworkFlowTCP &, PacketHeaderTCP &, TCPSession *);
};

#endif /* NetworkingTCP_h */
