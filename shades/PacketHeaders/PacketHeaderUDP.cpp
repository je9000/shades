#include "PacketHeaderUDP.hpp"

uint16_t PacketHeaderUDP::calculate_checksum() const {
    InetChecksumCalculator icc;
    icc.checksum_update(pbo.data(), pbo.size());
    return icc.checksum_finalize();
}

void PacketHeaderUDP::update_checksum() {
    checksum = 0;
    checksum = calculate_checksum();
}

void PacketHeaderUDP::check() const {
    // Checksum is optional in IPv4 and mandatory in IPv6.
    if ((checksum_matters || checksum() != 0) && (calculate_checksum() != 0)) throw invalid_packet("Checksum");
}

void PacketHeaderUDP::print(std::ostream &os) const {
    os << "UDP packet:\n";
    os << " Source Port: " << source_port() << "\n";
    os << " Desk Port: " << dest_port() << "\n";
    os << " Length: " << length() << "\n";
    os << " Checksum: " << checksum() << "\n";
}
