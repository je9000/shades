#include "NetworkingInput.hpp"
#include "StackTracePrinter.hpp"

size_t NetworkingInput::register_callback(const std::type_info &packet_type, const NetworkingInputCallback &callback, void *data) {
    return packet_type_callbacks[packet_type].add(callback, data);
}

void NetworkingInput::unregister_callback(const std::type_info &packet_type, const size_t id) {
    packet_type_callbacks[packet_type].remove(id);
}

size_t NetworkingInput::register_timer_callback(const NetworkingTimerCallback &callback, void *data) {
    return timer_callbacks.add(callback, data);
}

void NetworkingInput::unregister_timer_callback(const size_t id) {
    timer_callbacks.remove(id);
}

NetDriver &NetworkingInput::get_driver() {
    return net_driver;
}

void NetworkingInput::run() {
    PacketBuffer recv_into;
    keep_running = true;
    while(keep_running) process_one(recv_into);
}

void NetworkingInput::check_timers() {
    auto now = NetworkingInputSteadyClock::now();
    if (now >= last_packet_time + NETWORKING_INPUT_TIMER_INTERVAL) { // 1 second intervals. Why not.
        timer_callbacks.call_all(*this, now);
    }
}

void NetworkingInput::process_one(PacketBuffer &recv_into) {
    auto r = net_driver.recv(recv_into, NETWORKING_INPUT_TIMER_INTERVAL.count());
    check_timers();
    if (!r) return; // timeout

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
        if (packet_type_callbacks.count(typeid(invalid_packet))) packet_type_callbacks[typeid(invalid_packet)].call_all(*this, invalid_header);
    }
#ifndef DEBUG_NETWORKING_INPUT
    catch (const std::exception &e) {
        std::cerr << "Dropping packet, callback exception: " << e.what() << "\n";
        StackTracePrinter<20> stp;
        std::cerr << stp;
    }
#endif
}


bool NetworkingInput::process_ipv4(PacketBufferOffset ipv4_offset) {
    PacketHeaderIPv4 ipv4(ipv4_offset);
    if (packet_type_callbacks.count(typeid(PacketHeaderIPv4))) packet_type_callbacks[typeid(PacketHeaderIPv4)].call_until_false(*this, ipv4);

    if (ipv4.protocol() == IPPROTO::TCP) {
        PacketHeaderTCP tcp(ipv4.next_header_offset());
        if (packet_type_callbacks.count(typeid(PacketHeaderTCP))) packet_type_callbacks[typeid(PacketHeaderTCP)].call_until_false(*this, tcp);
    } else if (ipv4.protocol() == IPPROTO::UDP) {
        PacketHeaderUDP udp(ipv4.next_header_offset());
        if (packet_type_callbacks.count(typeid(PacketHeaderUDP))) packet_type_callbacks[typeid(PacketHeaderUDP)].call_until_false(*this, udp);
    } else if (ipv4.protocol() == IPPROTO::ICMP) {
        PacketHeaderICMP icmp(ipv4.next_header_offset());
        if (packet_type_callbacks.count(typeid(PacketHeaderICMP))) packet_type_callbacks[typeid(PacketHeaderICMP)].call_until_false(*this, icmp);
    }
    return true;
}

// return false to abort processing
bool NetworkingInput::process_ethernet(PacketBufferOffset ether_offset) {
    PacketHeaderEthernet ether(ether_offset);
    if (packet_type_callbacks.count(typeid(PacketHeaderEthernet))) packet_type_callbacks[typeid(PacketHeaderEthernet)].call_until_false(*this, ether);

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
