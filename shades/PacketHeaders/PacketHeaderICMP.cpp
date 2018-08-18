#include <string>

#include "HexDump.hpp"
#include "PacketHeaderICMP.hpp"

uint16_t PacketHeaderICMP::calculate_checksum() const {
    InetChecksumCalculator icc;
    icc.checksum_update(pbo.data(), pbo.size());
    return icc.checksum_finalize();
}

void PacketHeaderICMP::update_checksum() {
    checksum = 0;
    checksum = calculate_checksum();
}

void PacketHeaderICMP::check() const {
    if (calculate_checksum() != 0) throw invalid_packet("Checksum");
}

void PacketHeaderICMP::print(std::ostream &os) const {
    os << "ICMP packet:\n";
    os << " Type: " << static_cast<uint32_t>(type()) << "\n";
    os << " Code: " << static_cast<uint32_t>(code()) << "\n";
    os << " Checksum: " << checksum() << "\n";
}

void PacketHeaderICMPEcho::print(std::ostream &os) const {
    os << "ICMP Echo/Reply packet:\n";
    os << " Ident: " << static_cast<uint32_t>(ident()) << "\n";
    os << " Seq: " << static_cast<uint32_t>(seq()) << "\n";
    os << " Data: " << next_header_offset() << "\n";
}
