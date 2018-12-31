#ifndef OSNetwork_hpp
#define OSNetwork_hpp

#include <memory>
#include <unordered_map>

#include "PacketHeaderEthernet.hpp"
#include "PacketHeaderIPv4.hpp"

struct OSInterfaceInfo {
    std::string name;
    EthernetAddress ethernet_address;
    IPv4AddressAndMask ipv4_address;
    size_t mtu;
    bool up;
};

typedef std::unordered_map<std::string, OSInterfaceInfo> OSInterfacesMap;
typedef std::unique_ptr<OSInterfacesMap> OSInterfaces;

struct OSRouteInfo4 {
    size_t mtu;
    IPv4Address next_hop, dest_net, dest_mask;
};

class OSNetwork {
private:

public:
    static IPv4Address get_local_addr_for_remote(const IPv4Address &);
    static OSRouteInfo4 get_next_hop(const IPv4Address &);
    static OSInterfaces get_interfaces();
};

#endif /* OSNetwork_hpp  */
