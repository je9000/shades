#include <sstream>

#include "HexDump.hpp"
#include "PacketHeaderEthernet.hpp"

std::string EthernetAddress::as_string() const {
    std::ostringstream oss;
    
    oss << HexDump<EthernetAddressActual>(address, ':', 0);
    return oss.str();
}

void PacketHeaderEthernet::check() const {
    if (ether_type() <= 1500) throw invalid_packet("Raw IEEE 802.3, 802.2 not supported");
    if (ether_type() < 1536 /* && > 1500 */) throw invalid_packet("Invalid ethertype");
};

void PacketHeaderEthernet::build(const EthernetAddress &src_eth, const EthernetAddress &dest_eth, const ETHERTYPE::ETHERTYPE type) {
    dest = dest_eth;
    source = src_eth;
    ether_type = type;
}

std::ostream &operator<<(std::ostream &os, const EthernetAddress &ea) {
    os << HexDump<EthernetAddressActual>(ea.address, ':', 0);
    return os;
}

void PacketHeaderEthernet::print(std::ostream &os) const {
    os << "Ethernet frame:\n";
    os << " Dest MAC: " << dest() << "\n";
    os << " Source MAC: " << source() << "\n";
    os << " EtherType: " << ether_type() << " (" << ETHERNET_TYPE_INFO(ether_type()) << ")\n";
    //os << " Tag: " << tag() << "\n";
    //os << " CRC32: " << crc() << "\n";
}
