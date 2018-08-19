#ifndef IPv4RouteTable_h
#define IPv4RouteTable_h

#include <unordered_map>
#include <array>

#include "PacketHeaderIPv4.hpp"

// at() isn't used here because we bounds check mask_bits everywhere.

class IPv4RouteInfo {
public:
    IPv4Address next_hop;
    size_t mtu;
    IPv4RouteInfo(const IPv4Address &nh) : next_hop(nh), mtu(1500) {}
};

typedef std::unordered_map<IPv4Address, IPv4RouteInfo> IPv4RouteTableActual;

class IPv4RouteTable {
private:
    IPv4Address default_route;
    std::array<IPv4RouteTableActual, 32> routes_per_mask; // we don't store mask of /0
public:
    inline const IPv4Address get(const IPv4Address &dest) {
        for(size_t i = 32; i > 0; i--) {
            auto masked_dest = dest.apply_mask_bits(i);
            auto found = routes_per_mask[i - 1].find(masked_dest);
            if (found != routes_per_mask[i - 1].end()) {
                return found->second.next_hop;
            }
        };
        if (default_route) return default_route;
        throw std::runtime_error("No route to host");
    }

    inline void set(const IPv4Address &dest, size_t mask_bits, const IPv4Address &gw) {
        if (mask_bits > 32) throw std::out_of_range("Mask bits must be <= 32");
        if (!gw) throw std::runtime_error("Invalid gateway");
        if (mask_bits == 0) {
            default_route = gw;
            return;
        }
        auto masked_dest = dest.apply_mask_bits(mask_bits);
        auto &table = routes_per_mask[mask_bits - 1];
        if (table.find(masked_dest) != table.end()) table.erase(masked_dest);
        table.insert({masked_dest, gw});
    }
    
    inline void remove(const IPv4Address &dest, size_t mask_bits) {
        if (mask_bits > 32) throw std::out_of_range("Mask bits must be <= 32");
        if (mask_bits == 0) {
            default_route.ip_int = 0;
        } else {
            auto masked_dest = dest.apply_mask_bits(mask_bits);
            routes_per_mask[mask_bits - 1].erase(masked_dest);
        }
    }
    
};

#endif /* IPv4RouteTable_h */
