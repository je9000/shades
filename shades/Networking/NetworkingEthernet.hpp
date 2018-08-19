#ifndef NetworkingEthernet_h
#define NetworkingEthernet_h

#include <unordered_map>
#include <functional>
#include <memory>
#include <stdexcept>
#include <typeindex>

#include "IPv4RouteTable.hpp"
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
    
    bool process(PacketHeaderEthernet &);
    bool process_next_header(PacketHeaderEthernet &);
    
    void register_callback(const std::type_info &, const NetworkingEthernetInputCallback &, void * = nullptr);
    
    void send(const IPv4Address &, IPv4RouteTable &, const ETHERTYPE::ETHERTYPE, PacketBuffer &);
    void send(const EthernetAddress &, const ETHERTYPE::ETHERTYPE, PacketBuffer &);
    
    EthernetAddress arp_resolve(const IPv4Address &);
    void arp_callback(PacketHeaderEthernet &);
};

#endif /* NetworkingEthernet_h */
