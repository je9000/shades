#ifndef IPv4RouteTable_h
#define IPv4RouteTable_h

#include <unordered_map>
#include <array>

#include "PacketHeaderIPv4.hpp"

// at() isn't used here because we bounds check mask_bits everywhere.

class IPv4RouteInfo {
public:
    IPv4Address next_hop;
    uint32_t mtu;
    IPv4RouteInfo(const IPv4Address &nh, const uint32_t m = 0) : next_hop(nh), mtu(m) {}
    inline operator bool() const {
        return next_hop;
    }
};

typedef std::unordered_map<IPv4Address, IPv4RouteInfo> IPv4RouteTableActual;

class IPv4RouteTable {
private:
    IPv4RouteInfo default_route;
    std::array<IPv4RouteTableActual, 32> routes_per_mask; // we don't store mask of /0
public:
    IPv4RouteTable() : default_route(0) {}
    inline const IPv4RouteInfo get(const IPv4Address &dest) {
        for(size_t i = 32; i > 0; i--) {
            auto masked_dest = dest.apply_mask_bits(i);
            auto found = routes_per_mask[i - 1].find(masked_dest);
            if (found != routes_per_mask[i - 1].end()) {
                return found->second;
            }
        };
        if (default_route) return default_route;
        throw std::runtime_error("No route to host");
    }

    inline void set(const IPv4Address &dest, IPv4SubnetMask mask, const IPv4Address &gw, uint32_t mtu) {
        if (mask.mask > 32) throw std::out_of_range("Mask bits must be <= 32");
        if (mask.mask == 0) {
            default_route = {gw, mtu};
            return;
        }
        auto masked_dest = dest.apply_mask_bits(mask.mask);
        auto &table = routes_per_mask[mask.mask - 1];
        if (table.find(masked_dest) != table.end()) table.erase(masked_dest);
        table.insert({masked_dest, {gw, mtu}});
    }
    
    inline void remove(const IPv4Address &dest, IPv4SubnetMask mask) {
        if (mask.mask > 32) throw std::out_of_range("Mask bits must be <= 32");
        if (mask.mask == 0) {
            default_route.next_hop.ip_int = 0;
        } else {
            auto masked_dest = dest.apply_mask_bits(mask.mask);
            routes_per_mask[mask.mask - 1].erase(masked_dest);
        }
    }
};

#endif /* IPv4RouteTable_h */
