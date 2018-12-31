#ifndef NetworkingEthernet_h
#define NetworkingEthernet_h

#include <unordered_map>
#include <functional>
#include <memory>
#include <stdexcept>
#include <typeindex>

#include "CallbackVector.hpp"
#include "IPv4RouteTable.hpp"
#include "ARPTable.hpp"
#include "PacketHeaderEthernet.hpp"
#include "PacketHeaderARP.hpp"
#include "PacketHeader.hpp"

static const std::chrono::seconds ARP_QUERY_TIMEOUT(30); // seconds

// Callbacks
class NetworkingEthernet;
typedef std::function<void(NetworkingEthernet &, PacketHeaderEthernet &, void *)> NetworkingEthernetInputCallback;

class Networking;
class NetworkingEthernet {
private:
    std::unordered_map<std::type_index, CallbackVector<NetworkingEthernetInputCallback>> ethernet_callbacks;
    struct {
        size_t unknown_protocols = 0;
    } stats;
public:
    ARPTable arp_table;
    Networking &networking;
    bool silent = false;
    
    NetworkingEthernet(Networking &);
    
    bool process(PacketHeaderEthernet &);
    bool process_next_header(PacketHeaderEthernet &);
    
    size_t register_callback(const std::type_info &, const NetworkingEthernetInputCallback &, void * = nullptr);
    void unregister_callback(const std::type_info &, const size_t);
    
    void send(const IPv4Address &, IPv4RouteTable &, const ETHERTYPE::ETHERTYPE, PacketBuffer &, size_t = 0);
    void send(const EthernetAddress &, const ETHERTYPE::ETHERTYPE, PacketBuffer &, size_t = 0);
    
    EthernetAddress arp_resolve(const IPv4Address &);
    void arp_callback(PacketHeaderEthernet &);
};

#endif /* NetworkingEthernet_h */
