#include "NetworkingInput.hpp"

void NetworkingInput::register_callback(const std::type_info &packet_type, const NetworkingInputCallback &callback, void *data) {
    packet_type_callbacks[packet_type].push_back({callback, data});
}

void NetworkingInput::run() {
    keep_running = true;
    while(keep_running) process_one();
}

void NetworkingInput::process_one() {
    process_one(last_received);
}

// TODO: layer 3 only interfaces
void NetworkingInput::process_one(PacketBuffer &recv_into) {
    while(!net_driver.recv(recv_into));
    try {
        switch (recv_into.header_type) {
            case PacketBuffer::HEADER_ETHERNET:
                process_ethernet(recv_into);
                break;
                
            case PacketBuffer::HEADER_IPV4:
                process_ipv4(recv_into);
                break;
                
            // TODO ipv6
                
            default:
                break;
        }
    } catch (const invalid_packet &e) {
        PacketHeaderUnknown invalid_header(recv_into);
        for (auto callback : packet_type_callbacks[typeid(invalid_packet)]) {
            if (!callback.func(*this, invalid_header, callback.data)) break;
        }
    } catch (const std::exception &e) {
        std::cerr << "Dropping packet, callback exception: " << e.what() << "\n";
    }
}


bool NetworkingInput::process_ipv4(PacketBufferOffset ipv4_offset) {
    PacketHeaderIPv4 ipv4(ipv4_offset);
    ipv4.check();
    for (auto callback : packet_type_callbacks[typeid(PacketHeaderIPv4)]) {
        if (!callback.func(*this, ipv4, callback.data)) return false;
    }
    
    if (ipv4.protocol() == IPPROTO::TCP) {
        PacketHeaderTCP tcp(ipv4.next_header_offset());
        tcp.check();
        for (auto callback : packet_type_callbacks[typeid(PacketHeaderTCP)]) {
            if (!callback.func(*this, tcp, callback.data)) return false;
        }
    } if (ipv4.protocol() == IPPROTO::UDP) {
        PacketHeaderUDP udp(ipv4.next_header_offset());
        udp.check();
        for (auto callback : packet_type_callbacks[typeid(PacketHeaderUDP)]) {
            if (!callback.func(*this, udp, callback.data)) return false;
        }
    } else if (ipv4.protocol() == IPPROTO::ICMP) {
        PacketHeaderICMP icmp(ipv4.next_header_offset());
        icmp.check();
        for (auto callback : packet_type_callbacks[typeid(PacketHeaderICMP)]) {
            if (!callback.func(*this, icmp, callback.data)) return false;
        }
        
        if (icmp.type() == ICMP::ECHO) {
            PacketHeaderICMPEcho echo(icmp.next_header_offset());
            echo.check();
            for (auto callback : packet_type_callbacks[typeid(PacketHeaderICMPEcho)]) {
                if (!callback.func(*this, echo, callback.data)) return false;
            }
        }
    }
    return true;
}

// return false to abort processing
bool NetworkingInput::process_ethernet(PacketBufferOffset ether_offset) {
    PacketHeaderEthernet ether(ether_offset);
    ether.check();
    for (auto callback : packet_type_callbacks[typeid(PacketHeaderEthernet)]) {
        if (!callback.func(*this, ether, callback.data)) return false;;
    }
    switch (ether.ether_type()) {
        case ETHERTYPE::IP:
            process_ipv4(ether.next_header_offset());
            break;
            
        // case ipv6

        default:
            break;
    }
    return true;
}
