#ifndef NetworkingIPv4_hpp
#define NetworkingIPv4_hpp

#include <unordered_map>
#include <set>
#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <typeindex>

#include "IPv4RouteTable.hpp"
#include "PacketHeaderIPv4.hpp"
#include "PacketHeader.hpp"

using steady_clock = std::chrono::steady_clock;
using steady_clock_time = std::chrono::time_point<steady_clock>;

class NetworkFlowIPv4 {
public:
    IPv4Address source_ip;
    IPv4Address dest_ip;
    
    inline bool operator==(const NetworkFlowIPv4 &other) {
        return source_ip == other.source_ip && dest_ip == other.dest_ip;
    }
};

namespace std {
    template <>
    struct hash<const NetworkFlowIPv4> {
        std::size_t operator()(const NetworkFlowIPv4 &nfu) const {
            if (sizeof(std::size_t) >= 8) {
                return (static_cast<std::size_t>(nfu.source_ip.ip_int) << 32) | nfu.dest_ip.ip_int;
            } else {
                return nfu.source_ip.ip_int ^ nfu.dest_ip.ip_int;
            }
        }
    };
}

static const std::chrono::seconds IPV4_REASSEMBLY_TIMEOUT(30);
static const int IPV4_REASSEMBLY_MAX_PENDING = 100;

// Callbacks
class NetworkingIPv4;
typedef std::function<void(NetworkingIPv4 &, PacketHeaderIPv4 &, void *)> NetworkingIPv4InputCallback;
class NetworkingIPv4InputCallbackInfo {
public:
    NetworkingIPv4InputCallback func;
    void *data;
    NetworkingIPv4InputCallbackInfo(NetworkingIPv4InputCallback f, void *d) : func(f), data(d) {}
};

class ipv4_reassembly_timeout : std::runtime_error {
public:
    ipv4_reassembly_timeout() : std::runtime_error("IPv4 packet reassembly timed out") {}
};

class IPv4PacketPendingReassembly {
public:
    PacketBuffer pb;
    PacketHeaderIPv4 ip_header;
    size_t ipv4_data_len;
    uint16_t offset;
    
    // Copy the packet out of the input queue and into our own pending queue.
    IPv4PacketPendingReassembly(PacketHeaderIPv4 &ph) :
        pb(ph.backing_buffer()),
        ip_header(PacketBufferOffset(pb, ph.backing_buffer_offset())),
        ipv4_data_len(ph.size() - ph.header_size()),
        offset(ph.frag_offset())
    {}
    
    inline bool operator<(const IPv4PacketPendingReassembly &other) const {
        return offset < other.offset;
    }
    
    inline bool operator==(const IPv4PacketPendingReassembly &other) const {
        return offset == other.offset;
    }
};

class IPv4FlowData {
public:
};

// Set insures order and uniqueness, meaning we will drop any duplicate IP packets with the same offset.
// That's probably what we want.
typedef std::set<IPv4PacketPendingReassembly> IPv4FlowPacketsPendingReassembly;

class IPv4FlowPendingReassembly {
private:
    void check_fragment(PacketHeaderIPv4 &);
public:
    uint16_t ipid;
    bool have_first, have_last;
    steady_clock_time expires;
    IPv4FlowPacketsPendingReassembly packets;
    
    IPv4FlowPendingReassembly(PacketHeaderIPv4 &packet) :
        ipid(packet.ipid()),
        have_first(false),
        have_last(false),
        expires(steady_clock::now() + IPV4_REASSEMBLY_TIMEOUT)
    {
        add_packet(packet);
    }
    
    void add_packet(PacketHeaderIPv4 &);
    
    static bool needs_reassembly(PacketHeaderIPv4 &packet) {
        if (packet.flag_mf() || packet.frag_offset()) return true;
        return false;
    }
    
    std::unique_ptr<PacketBuffer> try_reassemble();
};

class Networking;
class NetworkingIPv4 {
private:
    Networking &networking;
    std::unordered_map<const NetworkFlowIPv4, IPv4FlowData> flows;
    std::unordered_map<uint16_t, IPv4FlowPendingReassembly> pending_reassembly;
    std::unordered_map<std::type_index, std::vector<const NetworkingIPv4InputCallbackInfo>> ipv4_callbacks;
    struct {
        size_t expired_fragmented = 0;
        size_t over_frag_limit = 0;
        size_t unknown_protocols = 0;
    } stats;
public:
    IPv4RouteTable routes;
    
    NetworkingIPv4(Networking &);
    
    void clean();
    
    void register_callback(const std::type_info &, const NetworkingIPv4InputCallback &, void * = nullptr);
    
    bool process_next_header(PacketHeaderIPv4 &);
    
    bool process(PacketHeaderIPv4 &);
    
    bool possibly_reassemble(PacketHeaderIPv4 &);
    
    void send(const IPv4Address &, const IPPROTO::IPPROTO, PacketBuffer &);
    
    bool icmp_echo_callback(NetworkingIPv4 &, PacketHeaderIPv4 &, void *);
};

#endif /* NetworkingIPv4_hpp */
