#ifndef NetworkingIPv4_hpp
#define NetworkingIPv4_hpp

#include <unordered_map>
#include <set>
#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <typeindex>
#include <random>

#include "CallbackVector.hpp"
#include "IPv4RouteTable.hpp"
#include "PacketHeaderIPv4.hpp"
#include "PacketHeader.hpp"

using NetworkingIPv4SteadyClock = std::chrono::steady_clock;
using NetworkingIPv4SteadyClockTime = std::chrono::time_point<NetworkingIPv4SteadyClock>;

class NetworkFlowIPv4 {
public:
    IPv4Address source, dest;
    uint16_t ipid;
    uint8_t proto;
    NetworkFlowIPv4(IPv4Address s, IPv4Address d, uint16_t id, uint8_t p) : source(s), dest(d), ipid(id), proto(p) {}

    inline bool operator==(const NetworkFlowIPv4 &other) const {
        return source == other.source && dest == other.dest && ipid == other.ipid && proto == other.proto;
    }
};

namespace std {
    template <>
    struct hash<const NetworkFlowIPv4> {
        inline std::size_t operator()(const NetworkFlowIPv4 &nfu) const {
            if (sizeof(std::size_t) >= 8) {
                return (static_cast<std::size_t>(nfu.source.ip_int) << 32) | (nfu.dest.ip_int ^ nfu.proto ^ nfu.ipid);
            } else {
                return (nfu.source.ip_int ^ nfu.dest.ip_int) | (nfu.dest.ip_int ^ nfu.proto ^ nfu.ipid);
            }
        }
    };
}

static const std::chrono::seconds IPV4_REASSEMBLY_TIMEOUT(30);
static const int IPV4_REASSEMBLY_MAX_PENDING = 100;

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

class IPv4IPIDCounter {
private:
    uint16_t last_assigned_id;
public:
    IPv4IPIDCounter() {
        std::random_device rd;
        last_assigned_id = rd();
        if (last_assigned_id == reserved_id()) last_assigned_id++;
    }
    
    inline uint16_t get_next_id() {
        last_assigned_id++;
        if (last_assigned_id == reserved_id()) last_assigned_id++;
        return last_assigned_id;
    }
    
    static uint16_t reserved_id() {
        return PacketHeaderIPv4::UNFRAGMENTED_ID;
    }
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
    NetworkingIPv4SteadyClockTime expires;
    IPv4FlowPacketsPendingReassembly packets;
    
    IPv4FlowPendingReassembly(PacketHeaderIPv4 &packet) :
        ipid(packet.ipid()),
        have_first(false),
        have_last(false),
        expires(NetworkingIPv4SteadyClock::now() + IPV4_REASSEMBLY_TIMEOUT)
    {
        add_packet(packet);
    }
    
    IPv4FlowPendingReassembly(const IPv4FlowPendingReassembly &) = delete;
    
    void add_packet(PacketHeaderIPv4 &);
    
    inline static bool needs_reassembly(PacketHeaderIPv4 &packet) {
        if (packet.flag_mf() || packet.frag_offset()) return true;
        return false;
    }
    
    std::unique_ptr<PacketBuffer> try_reassemble();
};

class NetworkingIPv4;
typedef std::function<void(size_t, void *, NetworkingIPv4 &, PacketHeaderIPv4 &)> NetworkingIPv4InputCallback;

class Networking;
class NetworkingIPv4 {
private:
    Networking &networking;
    IPv4IPIDCounter ip_id_counter;
    std::unordered_map<const NetworkFlowIPv4, IPv4FlowPendingReassembly> pending_reassembly;
    std::unordered_map<std::type_index, CallbackVector<NetworkingIPv4InputCallback, NetworkingIPv4 &, PacketHeaderIPv4 &>> ipv4_callbacks;
    struct {
        size_t expired_fragmented = 0;
        size_t over_frag_limit = 0;
        size_t unknown_protocols = 0;
    } stats;

    bool icmp_echo_callback(NetworkingIPv4 &, PacketHeaderIPv4 &);
    void timer_callback(NetworkingIPv4SteadyClockTime);
public:
    IPv4RouteTable routes;
    bool silent = false;
    
    NetworkingIPv4(Networking &);
    Networking &get_network();
    void clean(NetworkingIPv4SteadyClockTime);
    
    size_t register_callback(const std::type_info &, const NetworkingIPv4InputCallback &, void * = nullptr);
    void unregister_callback(const std::type_info &, const size_t);
    
    bool process_next_header(PacketHeaderIPv4 &);
    bool process(PacketHeaderIPv4 &);
    
    bool possibly_reassemble(PacketHeaderIPv4 &);
    
    void send(const IPv4Address &, const IPPROTO::IPPROTO, PacketBuffer &);
};

#endif /* NetworkingIPv4_hpp */
