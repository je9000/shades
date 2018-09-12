#ifndef ARPTable_h
#define ARPTable_h

#include <unordered_map>
#include <chrono>

#include "PacketHeaderEthernet.hpp"
#include "PacketHeaderIPv4.hpp"

// Arbitrary values.
static const std::chrono::seconds DEFAULT_ARP_CACHE_TIME(600);
static const size_t ARP_TABLE_MAX_ENTRIES = 2000;

using ARPTableSteadyClock = std::chrono::steady_clock;
using ARPTableSteadyClockTime = std::chrono::time_point<ARPTableSteadyClock>;

class arp_entry_not_found : std::runtime_error {
public:
    arp_entry_not_found() : std::runtime_error("ARP entry not found") {}
};

struct ARPTableEntry {
public:
    EthernetAddress hwaddr;
    ARPTableSteadyClockTime expires;
    ARPTableEntry(const EthernetAddress &eth, ARPTableSteadyClockTime ex) : hwaddr(eth), expires(ex) {}

    ARPTableEntry(const ARPTableEntry &other) {
        hwaddr = other.hwaddr;
        expires = other.expires;
    }
};

class ARPTable {
private:
    std::unordered_map<IPv4Address, ARPTableEntry> table;
public:
    const EthernetAddress at(const IPv4Address &ip) {
        auto found = table.find(ip);
        if (found == table.end()) throw arp_entry_not_found();
        if (found->second.expires.time_since_epoch().count() && ARPTableSteadyClock::now() >= found->second.expires) {
            table.erase(ip);
            throw arp_entry_not_found();
        }
        return found->second.hwaddr;
    }
    
    void insert_or_assign(const IPv4Address &ip, const EthernetAddress &eth) {
        insert_or_assign(ip, eth, DEFAULT_ARP_CACHE_TIME);
    }
    
    void insert_or_assign(const IPv4Address &ip, const EthernetAddress &eth, std::chrono::seconds duration) {
        ARPTableSteadyClockTime expire_time;
        if (table.size() >= ARP_TABLE_MAX_ENTRIES) throw std::out_of_range("No room in ARP table");
        if (duration.count()) {
            expire_time = ARPTableSteadyClock::now() + duration;
        }
        ARPTableEntry entry(eth, expire_time);
        if (table.find(ip) != table.end()) table.erase(ip);
        table.insert({ip, entry});
    }
    
    void clean() {
        auto now = ARPTableSteadyClock::now();
        for(auto it = table.begin(); it != table.end(); ) {
            if (it->second.expires.time_since_epoch().count() && now >= it->second.expires) {
                it = table.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    //TODO remove?
};


#endif /* ARPTable_h */
