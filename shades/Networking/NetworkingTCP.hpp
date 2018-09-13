#ifndef NetworkingTCP_h
#define NetworkingTCP_h

#include "PacketHeaderIPv4.hpp"
#include "PacketHeaderTCP.hpp"

#include <cstdint>
#include <unordered_map>

class NetworkFlowIPv4TCP;
typedef std::function<bool(void *, NetworkFlowIPv4TCP &, PacketHeaderTCP &)> NetworkFlowIPv4TCPCallback;
class NetworkFlowIPv4TCPCallbackInfo {
public:
    NetworkFlowIPv4TCPCallback func;
    void *data = nullptr;
};

class NetworkingTCP;
class TCPSession {
private:
    NetworkingTCP &net_tcp;
    NetworkFlowIPv4TCPCallbackInfo accept_callback;
    NetworkFlowIPv4TCPCallbackInfo data_callback;

    uint32_t last_sent_seq, last_sent_ack;
    uint32_t initial_seq;

    // TODO window and stuff
public:
    TCPSession(NetworkingTCP &);
    void accept(const NetworkFlowIPv4TCP &, const PacketHeaderTCP &);
    void process(const NetworkFlowIPv4TCP &, const PacketHeaderTCP &);
    
    static bool is_handshake_1(const PacketHeaderTCP &tcp) {
        return (tcp.syn() && !tcp.ack() && !tcp.fin() && !tcp.psh() && !tcp.rst());
    }
    
    static bool is_handshake_2(const PacketHeaderTCP &tcp) {
        return (tcp.syn() && tcp.ack() && !tcp.fin() && !tcp.psh() && !tcp.rst());
    }
};

class NetworkFlowIPv4TCP {
public:
    IPv4Address remote_ip, local_ip;
    uint16_t remote_port, local_port;
    
    NetworkFlowIPv4TCP(IPv4Address rip, uint16_t rport, IPv4Address lip, uint16_t lport) :
        remote_ip(rip),
        local_ip(lip),
        remote_port(rport),
        local_port(lport)
    {}

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
    NetworkingIPv4 &net4;
    std::random_device rd;
    
    std::unordered_map<uint16_t, NetworkFlowIPv4TCPCallbackInfo> listening_ports;
    std::unordered_map<const NetworkFlowIPv4TCP, TCPSession> ipv4_flows;
    struct {
        size_t unmatched_session = 0;
    } stats;
public:
    NetworkingTCP(NetworkingIPv4 &n);

    std::random_device &random_device() { return rd; }
    void process(PacketHeaderIPv4 &);
    
    void register_listener(const uint16_t, NetworkFlowIPv4TCPCallback &, void * = nullptr);
    void unregister_listener(const uint16_t);
    
    void send_rst(const NetworkFlowIPv4TCP &, const PacketHeaderTCP &);
    void send(const NetworkFlowIPv4TCP &, PacketBuffer &);
};

#endif /* NetworkingTCP_h */
