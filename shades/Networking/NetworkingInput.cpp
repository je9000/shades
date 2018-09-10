#include "NetworkingInput.hpp"

void NetworkingInput::register_callback(const std::type_info &packet_type, const NetworkingInputCallback &callback, void *data) {
    packet_type_callbacks[packet_type].push_back({callback, data});
}

void NetworkingInput::register_timer_callback(const NetworkingTimerCallback &callback, void *data) {
    timer_callbacks.push_back({callback, data});
}

void NetworkingInput::run() {
    PacketBuffer recv_into;
    keep_running = true;
    while(keep_running) process_one(recv_into);
}

void NetworkingInput::process_one(PacketBuffer &recv_into) {
    while(true) {
        if (net_driver.recv(recv_into)) break;
        auto now = NetworkingInputSteadyClock::now();
        for (auto callback : timer_callbacks) callback.func(*this, now, callback.data);
    }
#ifndef DEBUG_NETWORKING_INPUT
    try {
#endif
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
#ifndef DEBUG_NETWORKING_INPUT
    } catch (const invalid_packet &e) {
        PacketHeaderUnknown invalid_header(recv_into);
        for (auto callback : packet_type_callbacks[typeid(invalid_packet)]) {
            if (!callback.func(*this, invalid_header, callback.data)) break;
        }
    } catch (const std::exception &e) {
        std::cerr << "Dropping packet, callback exception: " << e.what() << "\n";
    }
#endif
}


bool NetworkingInput::process_ipv4(PacketBufferOffset ipv4_offset) {
    PacketHeaderIPv4 ipv4(ipv4_offset);
    for (auto callback : packet_type_callbacks[typeid(PacketHeaderIPv4)]) {
        if (!callback.func(*this, ipv4, callback.data)) return false;
    }
    
    if (ipv4.protocol() == IPPROTO::TCP) {
        PacketHeaderTCP tcp(ipv4.next_header_offset());
        for (auto callback : packet_type_callbacks[typeid(PacketHeaderTCP)]) {
            if (!callback.func(*this, tcp, callback.data)) return false;
        }
    } if (ipv4.protocol() == IPPROTO::UDP) {
        PacketHeaderUDP udp(ipv4.next_header_offset());
        for (auto callback : packet_type_callbacks[typeid(PacketHeaderUDP)]) {
            if (!callback.func(*this, udp, callback.data)) return false;
        }
    } else if (ipv4.protocol() == IPPROTO::ICMP) {
        PacketHeaderICMP icmp(ipv4.next_header_offset());
        for (auto callback : packet_type_callbacks[typeid(PacketHeaderICMP)]) {
            if (!callback.func(*this, icmp, callback.data)) return false;
        }
        
        if (icmp.type() == ICMP::ECHO) {
            PacketHeaderICMPEcho echo(icmp.next_header_offset());
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
