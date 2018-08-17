#ifndef NetworkingIPv4_hpp
#define NetworkingIPv4_hpp

#include <unordered_map>
#include <set>
#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>

#include "IPv4RouteTable.hpp"
#include "PacketHeaderIPv4.hpp"
#include "PacketHeader.hpp"

using steady_clock = std::chrono::steady_clock;
using steady_clock_time = std::chrono::time_point<steady_clock>;

class NetworkFlowIPv4 {
public:
    IPv4Address source_ip;
    IPv4Address dest_ip;
    
    bool operator==(const NetworkFlowIPv4 &other) {
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
    
    bool operator<(const IPv4PacketPendingReassembly &other) const {
        return offset < other.offset;
    }
    
    bool operator==(const IPv4PacketPendingReassembly &other) const {
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
    void check_fragment(PacketHeaderIPv4 &packet) {
        if (packet.ipid() != ipid || !needs_reassembly(packet)) throw std::runtime_error("packet isn't fragmented or wrong ip_id");
    }
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
    
    void add_packet(PacketHeaderIPv4 &packet) {
        check_fragment(packet);
        packets.emplace(packet);
        if (!packet.flag_mf()) have_last = true;
        if (!packet.frag_offset()) have_first = true;
        try_reassemble();
    }
    
    static bool needs_reassembly(PacketHeaderIPv4 &packet) {
        if (packet.flag_mf() || packet.frag_offset()) return true;
        return false;
    }
    
    std::unique_ptr<PacketBuffer> try_reassemble() {
        if (steady_clock::now() >= expires) throw ipv4_reassembly_timeout();
        if (!have_last || !have_first) return nullptr;
        
        size_t expected_next_offset = 0;
        size_t total_ipv4_content_size = 0;
        for (auto &p : packets) {
            if (p.offset != expected_next_offset) return nullptr;
            expected_next_offset += p.ipv4_data_len / 8;
            total_ipv4_content_size += p.ipv4_data_len;
        }
        // Allocate a new pb large enough to hold total_ipv4_content_size
        
        auto &ip_header = packets.begin()->ip_header;
        auto new_buf = std::make_unique<PacketBuffer>(total_ipv4_content_size + ip_header.header_size());
        PacketHeaderIPv4 new_ipv4(*new_buf);
        ip_header.copy_header_to(new_ipv4);
        PacketBufferOffset ip_data_pbo = new_ipv4.next_header_offset();
        size_t data_offset = 0;
        for (auto &p : packets) {
            ip_data_pbo.copy_from(p.ip_header.next_header_offset(), p.ip_header.data_size(), data_offset);
            data_offset += p.ip_header.data_size();
        }
        return new_buf;
    }
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
    
    NetworkingIPv4(Networking &n) : networking(n) {}
    
    void clean() {
        auto now = steady_clock::now();
        for (auto it = pending_reassembly.begin(); it != pending_reassembly.end(); ++it) {
            if (now >= it->second.expires) {
                pending_reassembly.erase(it);
                stats.expired_fragmented++;
            }
        }
    }
    
    void register_callback(const std::type_info &packet_type, const NetworkingIPv4InputCallback &callback, void *data = nullptr) {
        ipv4_callbacks[packet_type].push_back({callback, data});
    }
    
    bool process_next_header(PacketHeaderIPv4 &packet) {
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
    
    bool process(PacketHeaderIPv4 &packet) {
        if (IPv4FlowPendingReassembly::needs_reassembly(packet)) {
            return possibly_reassemble(packet);
        }
        return process_next_header(packet);
    }
    
    bool possibly_reassemble(PacketHeaderIPv4 &packet) {
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
                PacketHeaderIPv4 assembeled_ipv4(*r);
                return process_next_header(assembeled_ipv4);
            }
        } catch (ipv4_reassembly_timeout) {
            pending_reassembly.erase(pending);
        }

        return true;
    }
};

#endif /* NetworkingIPv4_hpp */
