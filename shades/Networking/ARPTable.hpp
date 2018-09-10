#ifndef ARPTable_h
#define ARPTable_h

#include <unordered_map>
#include <chrono>

#include "PacketHeaderEthernet.hpp"
#include "PacketHeaderIPv4.hpp"

static const std::chrono::seconds DEFAULT_ARP_CACHE_TIME(600);
using ARPTableSteadyClock = std::chrono::steady_clock;
using ARPTableSteadyClockTime = std::chrono::time_point<ARPTableSteadyClock>;

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
        ARPTableEntry found = table.at(ip);
        if (found.expires.time_since_epoch().count()) {
            if (ARPTableSteadyClock::now() > found.expires) {
                table.erase(ip);
                throw std::out_of_range("arp entry not found");
            }
        }
        return found.hwaddr;
    }
    
    void insert_or_assign(const IPv4Address &ip, const EthernetAddress &eth) {
        insert_or_assign(ip, eth, DEFAULT_ARP_CACHE_TIME);
    }
    
    void insert_or_assign(const IPv4Address &ip, const EthernetAddress &eth, std::chrono::seconds duration) {
        ARPTableSteadyClockTime expire_time;
        if (duration.count()) {
            expire_time = ARPTableSteadyClock::now() + duration;
        }
        ARPTableEntry entry(eth, expire_time);
        if (table.find(ip) != table.end()) table.erase(ip);
        table.insert({ip, entry});
    }
    
    //TODO remove? max size limit? clean on a timer?
};


#endif /* ARPTable_h */
