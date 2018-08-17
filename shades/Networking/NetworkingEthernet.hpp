#ifndef NetworkingEthernet_h
#define NetworkingEthernet_h

#include <unordered_map>
#include <functional>
#include <memory>
#include <stdexcept>

#include "ARPTable.hpp"
#include "PacketHeaderEthernet.hpp"
#include "PacketHeaderARP.hpp"
#include "PacketHeader.hpp"

// Callbacks
class NetworkingEthernet;
typedef std::function<void(NetworkingEthernet &, PacketHeaderEthernet &, void *)> NetworkingEthernetInputCallback;
class NetworkingEthernetInputCallbackInfo {
public:
    NetworkingEthernetInputCallback func;
    void *data;
    NetworkingEthernetInputCallbackInfo(NetworkingEthernetInputCallback f, void *d) : func(f), data(d) {}
};

class Networking;
class NetworkingEthernet {
private:
    std::unordered_map<std::type_index, std::vector<const NetworkingEthernetInputCallbackInfo>> ethernet_callbacks;
    struct {
        size_t unknown_protocols = 0;
    } stats;
public:
    ARPTable arp_table;
    Networking &networking;
    
    NetworkingEthernet(Networking &n) : networking(n) {}
    
    bool process(PacketHeaderEthernet &packet) {
        return process_next_header(packet);
    }
    
    void register_callback(const std::type_info &packet_type, const NetworkingEthernetInputCallback &callback, void *data = nullptr) {
        ethernet_callbacks[packet_type].push_back({callback, data});
    }
    
    bool process_next_header(PacketHeaderEthernet &packet) {
        decltype(ethernet_callbacks)::const_iterator callbacks;
        switch (packet.ether_type()) {
            case ETHERTYPE::IP:
                callbacks = ethernet_callbacks.find(typeid(PacketHeaderIPv4));
                break;
                
            /*case ETHERTYPE::IPV6:
                callbacks = ethernet_callbacks.find(typeid(PacketHeaderIPv6));
                break;*/
                
            case ETHERTYPE::ARP:
                arp_callback(packet);
                callbacks = ethernet_callbacks.find(typeid(PacketHeaderARP));
                break;
                
            default:
                stats.unknown_protocols++;
                return true;
        }
        if (callbacks == ethernet_callbacks.end()) return true;
        for (auto &cb : callbacks->second) {
            cb.func(*this, packet, cb.data);
        }
        return true;
    }
    
    void arp_callback(PacketHeaderEthernet &);
};

#endif /* NetworkingEthernet_h */
