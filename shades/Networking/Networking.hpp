#ifndef Networking_h
#define Networking_h

#include <functional>
#include <chrono>
#include <string_view>
#include <memory>

#include "NetworkingInput.hpp"
#include "NetDriver.hpp"
#include "PacketHeaders.hpp"
#include "PacketQueue.hpp"
#include "NetworkingEthernet.hpp"
#include "NetworkingIPv4.hpp"
#include "NetworkingTCP.hpp"

enum NetworkingLayers {
    //UNSPECIFIED = 0,
    ETHERNET = 1,
    IP = 2,
    TCP = 3
};

class Networking {
protected:
    friend NetworkingEthernet; // So the ARP query can block.
    NetworkingInput &net_in;
    PacketQueue<100> packet_queue;
    bool promiscuous;
public:
    NetDriver &net_driver;
    EthernetAddress my_mac;
    IPv4Address my_ip;
    IPv4SubnetMask my_subnet_mask;
    NetworkingEthernet eth_layer;
    std::unique_ptr<NetworkingIPv4> ipv4_layer;
    std::unique_ptr<NetworkingTCP> tcp_layer;

    Networking(NetworkingInput &, const NetworkingLayers, const std::string_view = "");
    Networking(NetworkingInput &, const NetworkingLayers, const IPv4AddressAndMask &, const std::string_view = "");

    // Implements ethernet promiscuous mode.
    bool ethernet_callback(PacketHeader &);
    
    // IPv4 promiscuous mode check before hading off to the IPv4 layer. Maybe should be handled there?
    bool ipv4_callback(PacketHeader &);

    void run();
    void process_one();
    
    NetworkingInput &get_input();
    
    EthernetAddress get_interface_addr(const std::string &);
    
    void run_init_command(const std::string_view);
};

#endif /* Networking_h */
