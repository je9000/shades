#ifndef NetworkingInput_h
#define NetworkingInput_h

#include <typeinfo>
#include <typeindex>
#include <unordered_map>
#include <vector>
#include <functional>

#include "PacketHeaders.hpp"
#include "NetDriver.hpp"

class NetworkingInput;
typedef std::function<bool(NetworkingInput &, PacketHeader & /* First */, PacketHeader & /* Last */, void *)> NetworkingInputCallback;
class NetworkingInputCallbackInfo {
public:
    NetworkingInputCallback func;
    void *data;
    NetworkingInputCallbackInfo(NetworkingInputCallback f, void *d) : func(f), data(d) {}
};

class NetworkingInput {
private:
    NetDriver &net_driver;
    PacketBuffer last_received;
    
    std::unordered_map<std::type_index, std::vector<const NetworkingInputCallbackInfo>> packet_type_callbacks;
public:
    bool keep_running;

    NetworkingInput(NetDriver &nd) : net_driver(nd), keep_running(false) {}
    
    void register_callback(const std::type_info &packet_type, const NetworkingInputCallback &callback, void *data = nullptr) {
        packet_type_callbacks[packet_type].push_back({callback, data});
    }
    
    void run() {
        keep_running = true;
        while(keep_running) process_one();
    }

    void process_one() {
        process_one(last_received);
    }

    // TODO: layer 3 only interfaces
    void process_one(PacketBuffer &recv_into) {
        while(!net_driver.recv(recv_into));
        try {
            PacketHeaderEthernet ether(recv_into);
            ether.check();
            for (auto callback : packet_type_callbacks[typeid(PacketHeaderEthernet)]) {
                if (!callback.func(*this, ether, ether, callback.data)) goto ABORT_PROCESSING;
            }
            
            if (ether.ether_type() == ETHERTYPE::IP) {
                PacketHeaderIPv4 ipv4(ether.next_header_offset());
                ipv4.check();
                for (auto callback : packet_type_callbacks[typeid(PacketHeaderIPv4)]) {
                    if (!callback.func(*this, ether, ipv4, callback.data)) goto ABORT_PROCESSING;
                }
                
                if (ipv4.protocol() == IPPROTO::TCP) {
                    PacketHeaderTCP tcp(ipv4.next_header_offset());
                    tcp.check();
                    for (auto callback : packet_type_callbacks[typeid(PacketHeaderTCP)]) {
                        if (!callback.func(*this, ether, tcp, callback.data)) goto ABORT_PROCESSING;
                    }
                } if (ipv4.protocol() == IPPROTO::UDP) {
                    PacketHeaderUDP udp(ipv4.next_header_offset());
                    udp.check();
                    for (auto callback : packet_type_callbacks[typeid(PacketHeaderUDP)]) {
                        if (!callback.func(*this, ether, udp, callback.data)) goto ABORT_PROCESSING;
                    }
                } else if (ipv4.protocol() == IPPROTO::ICMP) {
                    PacketHeaderICMP icmp(ipv4.next_header_offset());
                    icmp.check();
                    for (auto callback : packet_type_callbacks[typeid(PacketHeaderICMP)]) {
                        if (!callback.func(*this, ether, icmp, callback.data)) goto ABORT_PROCESSING;
                    }
                    
                    if (icmp.type() == ICMP::ECHO) {
                        PacketHeaderICMPEcho echo(icmp.next_header_offset());
                        echo.check();
                        for (auto callback : packet_type_callbacks[typeid(PacketHeaderICMPEcho)]) {
                            if (!callback.func(*this, ether, echo, callback.data)) goto ABORT_PROCESSING;
                        }
                    }
                }
            } else if (ether.ether_type() == ETHERTYPE::ARP) {
                PacketHeaderARP arp(ether.next_header_offset());
                arp.check();
                for (auto callback : packet_type_callbacks[typeid(PacketHeaderARP)]) {
                    if (!callback.func(*this, ether, arp, callback.data)) goto ABORT_PROCESSING;
                }
            }
        ABORT_PROCESSING:
            ;
        } catch (const invalid_packet &e) {
            PacketHeaderUnknown invalid_header(recv_into);
            for (auto callback : packet_type_callbacks[typeid(invalid_packet)]) {
                if (!callback.func(*this, invalid_header, invalid_header, callback.data)) break;
            }
        } catch (const std::exception &e) {
            std::cerr << "Dropping packet, callback exception: " << e.what() << "\n";
        }
    }
};

#endif /* NetworkingInput_h */
