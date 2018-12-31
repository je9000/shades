#include "Networking.hpp"
#include "OSNetwork.hpp"

#include <unistd.h>
#include <sys/wait.h>

Networking::Networking(NetworkingInput &ni, const IPv4AddressAndMask my_address_and_mask, const std::string_view init_command) :
    net_in(ni),
    promiscuous(false),
    net_driver(ni.get_driver()),
    eth_layer(*this),
    ipv4_layer(*this),
    tcp_layer(&ipv4_layer)
{
    // assign ip? dhcp?
    my_subnet_mask = my_address_and_mask.mask;
    my_ip = my_address_and_mask.addr;

    IPv4Address all_zero_ip(0);
    ipv4_layer.routes.set(my_ip, my_subnet_mask, all_zero_ip, ni.get_driver().get_mtu());
    
    run_init_command(init_command);

    if (!net_driver.is_layer3_interface()) {
        my_mac = get_interface_addr(net_driver.get_ifname());
        net_in.register_callback(typeid(PacketHeaderEthernet),
                                 [this](size_t, void *d, NetworkingInput &, PacketHeader &ph) { return ethernet_callback(ph); }
                                 );
    }
    net_in.register_callback(typeid(PacketHeaderIPv4),
                             [this](size_t, void *d, NetworkingInput &, PacketHeader &ph) { return ipv4_callback(ph); }
                             );
}

// Implements ethernet promiscuous mode.
bool Networking::ethernet_callback(PacketHeader &ph) {
    auto &eth = dynamic_cast<PacketHeaderEthernet &>(ph);
    if (eth.dest()[0] & ETHERNET_MULTICAST_BIT || eth.dest() == my_mac) return eth_layer.process(eth);
    if (promiscuous) return true;
    return false;
}

// IPv4 promiscuous mode check before hading off to the IPv4 layer. Maybe should be handled there?
bool Networking::ipv4_callback(PacketHeader &ph) {
    auto &ip = dynamic_cast<PacketHeaderIPv4 &>(ph);
    if (ip.dest() == my_ip || ip.dest() == 0xFFFFFFFF) return ipv4_layer.process(ip); // Missing multicast blocks
    if (promiscuous) return true;
    return false;
}

void Networking::run() {
    PacketBuffer recv_into;
    net_in.keep_running = true;
    while(net_in.keep_running) {
        if (auto *buf = packet_queue.get_readable()) {
            net_in.process_one(*buf);
            packet_queue.put_writable(buf); // We're done with it.
        } else {
            net_in.process_one(recv_into);
        }
    }
}

NetworkingInput &Networking::get_input() {
    return net_in;
}

EthernetAddress Networking::get_interface_addr(const std::string &ifn) {
    auto ifs = OSNetwork::get_interfaces();
    return ifs->at(ifn).ethernet_address;
}

void Networking::run_init_command(const std::string_view init_command) {
    if (init_command.empty()) return;
    
    pid_t parent_pid = getpid();
    if (!fork()) {
        setenv("_PID", std::to_string(parent_pid).data(), 1);
        setenv("_IFNAME", net_driver.get_ifname().data(), 1);
        setenv("_IPV4_ADDRESS", my_ip.as_string().data(), 1);
        setenv("_IPV4_NETMASK", my_subnet_mask.as_string().data(), 1);
        if (net_driver.is_layer3_interface()) {
            setenv("_LAYER_3_ONLY", "1", 1);
        } else {
            setenv("_LAYER_3_ONLY", "0", 1);
            setenv("_ETHERNET_ADDRESS", my_mac.as_string().data(), 1);
        }
        system(init_command.data());
        exit(0);
    } else {
        wait(nullptr);
    }
}
