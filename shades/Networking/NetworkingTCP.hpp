#ifndef NetworkingTCP_h
#define NetworkingTCP_h

#include "PacketHeaderIPv4.hpp"
#include "PacketHeaderTCP.hpp"

#include <cstdint>
#include <unordered_map>
#include <chrono>

#define DEBUG_TCP_STATE_TRANSITIONS

using NetworkingTCPSteadyClock = std::chrono::steady_clock;
using NetworkingTCPSteadyClockTime = std::chrono::time_point<NetworkingIPv4SteadyClock>;
static const std::chrono::seconds NETWORKING_TCP_TIME_WAIT_TIMEOUT(60);
static const int NETWORKING_TCP_MAX_KEEPALIVES = 3;

enum TCP_IP_VERSION {
    PROTO_IPv4 = 4,
    PROTO_IPv6 = 6,
};

const int NETWORK_TCP_MINIMUM_WINDOW_SIZE = 8;

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
public:
    TCPConnectionState(TCPConnectionStates new_state) : current_state(new_state) {}
    TCPConnectionStates operator=(const TCPConnectionStates new_state) {
#ifdef DEBUG_TCP_STATE_TRANSITIONS
        std::clog << "TCP state transitioning from " << current_state << " to " << new_state << "\n";
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

class NetworkFlowTCP;
class TCPSession;
typedef std::function<TCPSessionAction(TCPSessionEvent, const NetworkFlowTCP &, const TCPSession *, const PacketHeaderTCP &)> NetworkFlowTCPCallback;
class NetworkFlowTCPCallbackInfo {
public:
    NetworkFlowTCPCallback func;
};

class NetworkingTCP;
class TCPSession {
private:
    friend NetworkingTCP;
    struct {
        size_t packets_sent, packets_received, bytes_sent, bytes_received,
               out_of_window, out_of_window_rst, duplicate_packets;
    } stats;
public:
    // IPv4 specific. Need a way to make this generic.
    NetworkingTCP &net_tcp;
    const NetworkFlowTCP &flow;
    NetworkFlowTCPCallbackInfo callback;

    TCPConnectionState state;
    NetworkingTCPSteadyClockTime state_change_time;
    NetworkingTCPSteadyClockTime last_recv_time;

    uint32_t last_sent_seq, next_expected_seq;
    uint_fast32_t peer_window_size, my_window_size;
    uint_fast8_t keepalives_sent;

    TCPSession(NetworkingTCP &, const NetworkFlowTCP &);
    void process(const PacketHeaderTCP &);
    void run_callback(TCPSessionEvent, const PacketHeaderTCP &);
    bool check_packet_in_window(const PacketHeaderTCP &);
    
    void send_rst();
    void send_ack();
    void send_fin();

    void keepalive();
    
    static bool is_handshake_syn(const PacketHeaderTCP &tcp) {
        // The first part of the handshake has to be a SYN packet with no other flags set.
        return (tcp.syn() && !tcp.ack() && !tcp.fin() && !tcp.psh() && !tcp.rst() && tcp.window_size() >= NETWORK_TCP_MINIMUM_WINDOW_SIZE);
    }
    
    static bool is_handshake_synack(const PacketHeaderTCP &tcp) {
        return (tcp.syn() && tcp.ack() && !tcp.fin() && !tcp.psh() && !tcp.rst());
    }
};

class NetworkFlowTCP {
public:
    uint_fast16_t remote_port, local_port;
    
    NetworkFlowTCP(uint_fast16_t lport, uint_fast16_t rport) :
        local_port(lport),
        remote_port(rport)
    {}
    
    virtual ~NetworkFlowTCP() {};
    virtual TCP_IP_VERSION ip_ver() const = 0;
};

class NetworkFlowIPv4TCP : public NetworkFlowTCP {
public:
    IPv4Address remote_ip, local_ip;
    
    NetworkFlowIPv4TCP(IPv4Address rip, uint_fast16_t rport, IPv4Address lip, uint_fast16_t lport) :
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
    
    std::unordered_map<uint16_t, NetworkFlowTCPCallbackInfo> ipv4_listening_ports;
    std::unordered_map<const NetworkFlowIPv4TCP, TCPSession> ipv4_flows;
private:
    friend TCPSession;
    struct {
        size_t unmatched_session, recevied_out_of_window, recevied_on_closed,
               syn_to_closed_port, unmatched_rst, received_on_time_wait;
    } stats;
public:
    NetworkingTCP(NetworkingIPv4 *n);

    std::random_device &random_device() { return rd; }
    void process(PacketHeaderIPv4 &);
    void timer_callback(NetworkingInputSteadyClockTime);
    
    void register_listener(const TCP_IP_VERSION, const uint_fast16_t, const NetworkFlowTCPCallback &);
    void unregister_listener(const TCP_IP_VERSION, const uint_fast16_t);
    
    void send_rst(const NetworkFlowTCP &, uint32_t, TCPSession *);
    TCPSession send_accept(const NetworkFlowTCP &, const PacketHeaderTCP &, const NetworkFlowTCPCallbackInfo);
    void send(const NetworkFlowTCP &, PacketHeaderTCP &, TCPSession *);
};

#endif /* NetworkingTCP_h */
