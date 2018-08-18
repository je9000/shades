#ifndef NetworkingEthernet_h
#define NetworkingEthernet_h

#include <unordered_map>
#include <functional>
#include <memory>
#include <stdexcept>
#include <typeindex>

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
    
    void register_callback(const std::type_info &, const NetworkingEthernetInputCallback &, void *data = nullptr);
    
    bool process_next_header(PacketHeaderEthernet &);
    
    void arp_callback(PacketHeaderEthernet &);
};

#endif /* NetworkingEthernet_h */
