#include <memory>
#include "PacketHeaders.hpp"

/*
 PacketHeader *PacketBuffer::get_next_header() {
 PacketHeader *ph = std::experimental::any_cast<PacketHeader>(&(headers.back()));
 auto f = ph->recalculate_next_header();
 if (!f) throw std::runtime_error("Unable to locate next header!");
 headers.push_back(std::move(f));
 return std::experimental::any_cast<PacketHeader>(&(headers.back()));
 }
 */

std::unique_ptr<PacketHeader> PacketHeader::recalculate_next_header() const {
    auto type = this->backing_buffer().header_type;

    if (type == PacketBuffer::HEADER_ETHERNET) {
        const PacketHeaderEthernet *eth = dynamic_cast<const PacketHeaderEthernet *>(this);
        if (eth) return eth->recalculate_next_header();
    } else if (type == PacketBuffer::HEADER_IPV4) {
        const PacketHeaderIPv4 *ipv4 = dynamic_cast<const PacketHeaderIPv4 *>(this);
        if (ipv4) return ipv4->recalculate_next_header();
    } else if (type == PacketBuffer::HEADER_IPV6) {
        // todo
    }

    return nullptr;
}

std::unique_ptr<PacketHeader> PacketHeaderEthernet::recalculate_next_header() const {
    auto pbo = next_header_offset();
    
    switch (ether_type()) {
        case ETHERTYPE::IP:
            return std::make_unique<PacketHeaderIPv4>(pbo);
        case ETHERTYPE::ARP:
            return std::make_unique<PacketHeaderARP>(pbo);
        default:
            return nullptr; //std::make_unique<PacketHeaderUnknown>(pbo);
    }
}

std::unique_ptr<PacketHeader> PacketHeaderIPv4::recalculate_next_header() const {
    auto pbo = next_header_offset();
    
    switch (protocol()) {
        case IPPROTO::TCP:
            return std::make_unique<PacketHeaderTCP>(pbo);
        case IPPROTO::UDP:
            return std::make_unique<PacketHeaderUDP>(pbo);
        case IPPROTO::ICMP:
            return std::make_unique<PacketHeaderICMP>(pbo);
        default:
            return nullptr; //std::make_unique<PacketHeaderUnknown>(pbo);
    }
}
