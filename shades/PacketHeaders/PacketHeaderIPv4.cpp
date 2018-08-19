#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "HexDump.hpp"
#include "PacketHeaderIPv4.hpp"

IPv4Address IPv4Address::apply_mask_bits(size_t bits) const {
    if (bits == 0) return 0;
    if (bits > 32) throw std::out_of_range("Bits must be <= 32");
    return htonl(ntohl(ip_int) & ~((static_cast<uint64_t>(1) << (32 - bits)) - 1));
}

std::ostream &operator<<(std::ostream &os, const IPv4Address &ip4)
{
    os << ip4.as_string();
    return os;
}

// Subnetmask in dotted format.
void IPv4SubnetMask::assign(const std::string_view s) {
    uint32_t ip_int = ntohl(IPv4Address::str_to_ip(s)); // Make sure things are big-endian, since we're counting bits.
    uint32_t ones = 0;
    bool seen_zero = false;
    for (int bit = 31; bit >= 0; bit--) {
        if (ip_int & (static_cast<uint32_t>(1) << bit)) {
            if (seen_zero) throw std::runtime_error("Invalid subnet mask");
            ones++;
        } else {
            seen_zero = true;
        }
    }
    mask = ones;
}

void IPv4AddressAndMask::assign(const std::string_view am) {
    auto slash = am.find_first_of("/");
    if (slash != std::string_view::npos) {
        addr = am.substr(0, slash);
        unsigned int temp;
        if (std::sscanf(am.substr(slash + 1, am.size() - slash - 1).data(), "%u", &temp) != 1) throw std::runtime_error("Invalid subnet mask");
        mask = temp;
    } else {
        addr = am;
        mask = 32;
    }
}

uint16_t PacketHeaderIPv4::calculate_checksum() const {
    InetChecksumCalculator icc;
    icc.checksum_update(pbo.data(), header_size());
    return icc.checksum_finalize();
}

void PacketHeaderIPv4::update_checksum() {
    checksum = 0;
    checksum = calculate_checksum();
}

void PacketHeaderIPv4::check() const {
    if (version() != 4) throw invalid_packet("IPv4 header version != 4");
    if (header_length_qwords() > IPV4_MAX_HEADER_LENGTH_QWORDS || header_length_qwords() < IPV4_MIN_HEADER_LENGTH_QWORDS) throw invalid_packet("Header length");
    if (calculate_checksum() != 0) throw invalid_packet("Checksum");
}

void PacketHeaderIPv4::build(const IPv4Address src_ip, const IPv4Address dest_ip, const uint16_t data_size, const IPPROTO::IPPROTO next_protocol) {
    version(4);
    header_length_bytes(20);
    flags_frag_offset = 0;
    ipid = 0x4a45;  // RFC 6864 says this value is meaningless for unfragmented packets.
    dscp_ecn = 0;
    ttl = 64;
    source = src_ip;
    dest = dest_ip;
    protocol = next_protocol;
    size = data_size + header_length_bytes();
    update_checksum();
}

void PacketHeaderIPv4::print(std::ostream &os) const {
    os << "IPv4 packet:\n";
    os << " Version and IHL: " << static_cast<uint32_t>(vihl()) << "\n";
    os << "  Version: " << static_cast<uint32_t>(version()) << "\n";
    os << "  IHL: " << static_cast<uint32_t>(header_length_bytes()) << " (" << static_cast<uint32_t>(header_length_qwords()) << " qwords)\n";
    os << " DSCP and ECN: " << static_cast<uint32_t>(dscp_ecn()) << "\n";
    os << "  DSCP: " << static_cast<uint32_t>(dscp_bits()) << "\n";
    os << "  ECN: " << static_cast<uint32_t>(ecn_bits()) << "\n";
    os << " Size: " << size() << "\n";
    os << " ID: " << ipid() << "\n";
    os << " Flags and Frag Offset: " << flags_frag_offset() << "\n";
    os << "  Don't Fragment: " << flag_df() << "\n";
    os << "  More Fragments: " << flag_mf() << "\n";
    os << "  Fragment Offset: " << frag_offset() << "\n";
    os << " TTL: " << static_cast<uint32_t>(ttl()) << "\n";
    os << " Protocol: " << static_cast<uint32_t>(protocol()) << "\n";
    os << " Checksum: " << checksum() << "\n";
    os << " Source: " << source().as_string() << "\n";
    os << " Dest: " << dest().as_string() << "\n";
}
