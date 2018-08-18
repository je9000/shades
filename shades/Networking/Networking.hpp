#ifndef Networking_h
#define Networking_h

#include <functional>
#include <chrono>

#include "NetworkingInput.hpp"
#include "NetDriver.hpp"
#include "ARPTable.hpp"
#include "IPv4RouteTable.hpp"
#include "PacketHeaders.hpp"
#include "PacketQueue.hpp"
#include "NetworkingIPv4.hpp"
#include "NetworkingEthernet.hpp"

static const std::chrono::seconds ARP_QUERY_TIMEOUT(30); // seconds

class Networking {
private:
    NetworkingInput net_in;
    PacketQueue<100> packet_queue;
    bool promiscuous;
public:
    NetDriver &net_driver;
    EthernetAddress my_mac;
    IPv4Address my_ip;
    IPv4SubnetMask my_subnet_mask;
    NetworkingIPv4 ipv4_layer;
    NetworkingEthernet eth_layer;

    Networking(NetDriver &, const IPv4AddressAndMask);

    // Implements ethernet promiscuous mode.
    bool ethernet_callback(NetworkingInput &, PacketHeader &, PacketHeader &, void *);
    
    // IPv4 promiscuous mode check before hading off to the IPv4 layer. Maybe should be handled there?
    bool ipv4_callback(NetworkingInput &, PacketHeader &, PacketHeader &, void *);

    // Needs to be moved to an IPv4 layer callback so fragmentation is handled for us.
    bool icmp_echo_callback(NetworkingInput &, PacketHeader &, PacketHeader &, void *);
    
    void run();
    
    NetworkingInput &input();
    
    EthernetAddress get_interface_mac(const std::string_view);
    EthernetAddress arp_resolve(const IPv4Address &ip);
};

#endif /* Networking_h */
