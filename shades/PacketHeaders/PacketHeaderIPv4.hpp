#ifndef PacketHeaderIPv4_h
#define PacketHeaderIPv4_h

#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "HexDump.hpp"
#include "InetChecksum.hpp"
#include "PacketHeader.hpp"
#include "PacketBuffer.hpp"
#include "BufferOffsetType.hpp"

static const unsigned int IPV4_MAX_HEADER_LENGTH_QWORDS = 15;
static const unsigned int IPV4_MIN_HEADER_LENGTH_QWORDS = 5;

namespace IPPROTO {
    enum IPPROTO {
        IP = 0,
        ICMP = 1,
        IGMP = 2,
        IPIP = 4,
        TCP = 6,
        EGP = 8,
        PUP = 12,
        UDP = 17,
        IDP = 22,
        TP = 29,
        DCCP = 33,
        IPV6 = 41,
        RSVP = 46,
        GRE = 47,
        ESP = 50,
        AH = 51,
        MTP = 92,
        BEETPH = 94,
        ENCAP = 98,
        PIM = 103,
        COMP = 108,
        SCTP = 132,
        UDPLITE = 136,
        MPLS = 137,
        RAW = 255
    };
}

class IPv4Address {
public:
    uint32_t ip_int; // Stored in network byte order.

    IPv4Address() : ip_int(0) {};
    IPv4Address(uint32_t ip_int) : ip_int(ip_int) {};
    IPv4Address(const std::string_view s) : ip_int(str_to_ip(s)) {};
    
    std::string as_string() const {
        return ip_to_str(ip_int);
    };
    
    void operator=(const std::string_view ip) {
        ip_int = str_to_ip(ip);
    }
    
    static uint32_t str_to_ip(const std::string_view ip) {
        struct in_addr ia;
        std::string s(ip);
        if (!inet_pton(AF_INET, s.data(), &ia)) throw std::runtime_error("Invalid IPv4 address");
        return ia.s_addr;
    }
    
    static std::string ip_to_str(uint32_t ip_int) {
        char r[16] = {0};
        struct in_addr ia;
        ia.s_addr = ip_int;
        if (!inet_ntop(AF_INET, &ia, reinterpret_cast<char *>(&r), sizeof(r))) throw std::runtime_error("Invalid IPv4 address");
        return r;
    }
    
    void *data() {
        return &ip_int;
    }
    
    static size_t size() {
        return sizeof(ip_int);
    }
    
    bool operator==(const IPv4Address &other) const { return this->ip_int == other.ip_int; }
    bool operator!=(const IPv4Address &other) const { return this->ip_int != other.ip_int; }
    
    bool operator==(const uint32_t &other) const { return this->ip_int == other; }
    bool operator!=(const uint32_t &other) const { return this->ip_int != other; }
    
    bool operator==(const std::string_view other) const { return this->ip_int == str_to_ip(other); }
    bool operator!=(const std::string_view other) const { return this->ip_int != str_to_ip(other); }
    
    operator bool() const {
        return ip_int != 0;
    }
    
    IPv4Address apply_mask_bits(size_t bits) const {
        if (bits == 0) return 0;
        if (bits > 32) throw std::out_of_range("Bits must be <= 32");
        return htonl(ntohl(ip_int) & ~((static_cast<uint64_t>(1) << (32 - bits)) - 1));
    }
};

namespace std {
    template <>
    struct hash<IPv4Address> {
        size_t operator()(const IPv4Address &k) const {
            return k.ip_int;
        }
    };
}

std::ostream &operator<<(std::ostream &os, const IPv4Address &ip4)
{
    os << ip4.as_string();
    return os;
}

class IPv4SubnetMask {
private:
    uint_fast8_t mask;
public:
    IPv4SubnetMask(uint_fast8_t b = 32) { assign(b); }
    void operator=(uint_fast8_t b) { assign(b); }
    
    IPv4SubnetMask(const std::string_view s) { assign(s); }
    void operator=(const std::string_view s) { assign(s); }
    
    // Subnetmask in dotted format.
    void assign(const std::string_view s) {
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
    
    void assign(uint_fast8_t b) {
        if (b > 32) throw std::out_of_range("Subnet mask bits must be <= 32");
        mask = b;
    }
    
    bool same_network(const IPv4Address &n1, const IPv4Address &n2) {
        uint8_t bits = (static_cast<uint64_t>(1) << mask) - 1;
        return (n1.ip_int & bits) == (n2.ip_int & bits);
    }
    
    bool operator==(const IPv4SubnetMask &other) {
        return mask == other.mask;
    }
};

class IPv4AddressAndMask {
public:
    IPv4Address addr;
    IPv4SubnetMask mask;

    IPv4AddressAndMask(const IPv4Address a, const IPv4SubnetMask m = 32) : addr(a), mask(m) {}
    IPv4AddressAndMask(const std::string_view am) { assign(am); }
    void operator=(const std::string_view am) { assign(am); }
        
    void assign(const std::string_view am) {
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
    
    bool operator==(const IPv4AddressAndMask &other) {
        return (addr == other.addr && mask == other.mask);
    }
    
    bool contains(const IPv4Address &other) {
        return mask.same_network(addr, other);
    }
};

class IPv4Options {
private:
    size_t qwords = 0;
public:
    void resize_qwords(size_t new_size) {
        if (new_size + IPV4_MIN_HEADER_LENGTH_QWORDS > IPV4_MAX_HEADER_LENGTH_QWORDS) throw std::out_of_range("Invalid options size");
        qwords = new_size;
    }
    
    void resize_bytes(size_t new_size) {
        uint_fast8_t qw = new_size / 4;
        if (new_size % 4) qw++;
        resize_qwords(qw);
    }
    
    size_t size_in_bytes() {
        return qwords * 4; // quad words are 32-bits each
    }
};

class PacketHeaderIPv4 : public PacketHeader {
public:
    BufferOffsetType<0, uint8_t> vihl;
    BufferOffsetType<1, uint8_t> dscp_ecn;
    BufferOffsetType<2, uint16_t> size;
    BufferOffsetType<4, uint16_t> ipid;
    BufferOffsetType<6, uint16_t> flags_frag_offset;
    BufferOffsetType<8, uint8_t> ttl;
    BufferOffsetType<9, uint8_t> protocol;
    BufferOffsetType<10, InetChecksum> checksum;
    BufferOffsetType<12, IPv4Address> source;
    BufferOffsetType<16, IPv4Address> dest;
    IPv4Options options;
    
    PacketHeaderIPv4(PacketBufferOffset source_pbo) :
        PacketHeader(source_pbo),
        vihl(*this),
        dscp_ecn(*this),
        size(*this),
        ipid(*this),
        flags_frag_offset(*this),
        ttl(*this),
        protocol(*this),
        checksum(*this),
        source(*this),
        dest(*this)
    {}
    
    void print(std::ostream &) const;

    uint_fast8_t version() const {
        return vihl() >> 4;
    }
    
    void version(uint_fast8_t v) {
        vihl = (vihl() & 0b1111) | ((v & 0b1111) << 4);
    }
    
    uint_fast8_t header_length_qwords() const {
        return vihl() & 0b1111;
    }
    
    void header_length_qwords(uint_fast8_t l) {
        if (l > IPV4_MAX_HEADER_LENGTH_QWORDS || l < IPV4_MIN_HEADER_LENGTH_QWORDS) throw std::runtime_error("Invalid header length");
        vihl = (vihl() & 0b11110000) | (l & 0b1111);
    }
    
    uint_fast8_t header_length_bytes() const {
        return header_length_qwords() * 4;
    }
    
    void header_length_bytes(uint_fast8_t b) {
        uint_fast8_t qwords = b / 4;
        if (b % 4) qwords++;
        return header_length_qwords(qwords);
    }
    
    uint_fast8_t dscp_bits() const {
        return dscp_ecn() >> 2;
    }
    
    void dscp_bits(uint_fast8_t d) {
        dscp_ecn = (dscp_ecn() & 0b11) | ((d & 0b11) << 2);
    }
    
    uint_fast8_t ecn_bits() const {
        return dscp_ecn() & 0b11;
    }
    
    void ecn_bits(uint_fast8_t e) {
        dscp_ecn = (dscp_ecn() & 0b11111100) | (e & 0b11);
    }
    
    bool flag_reserved() const {
        return flags_frag_offset() >> 15;
    }
    
    void flag_reserved(bool val) {
        uint32_t v = val;
        flags_frag_offset = (flags_frag_offset() & 0b0111111111111111) | (v << 15);
    }
    
    bool flag_df() const {
        return (flags_frag_offset() >> 14) & 0b1;
    }
    
    void flag_df(bool val) {
        uint32_t v = val;
        flags_frag_offset = (flags_frag_offset() & 0b1011111111111111) | (v << 14);
    }
    
    bool flag_mf() const {
        return (flags_frag_offset() >> 13) & 0b1;
    }
    
    void flag_mf(bool val) {
        uint32_t v = val;
        flags_frag_offset = (flags_frag_offset() & 0b1101111111111111) | (v << 13);
    }
    
    uint_fast16_t frag_offset() const {
        return flags_frag_offset() & 0b0001111111111111;
    }
    
    void frag_offset(uint_fast16_t v) {
        flags_frag_offset = (flags_frag_offset() & 0b1110000000000000) | (v & 0b0001111111111111);
    }
    
    size_t header_size() const {
        return header_length_bytes();
    }
    
    size_t data_size() const {
        return size() - header_size();
    }
    
    uint16_t calculate_checksum() const {
        InetChecksumCalculator icc;
        icc.checksum_update(pbo.data(), header_size());
        return icc.checksum_finalize();
    }
    
    void update_checksum() {
        checksum = 0;
        checksum = calculate_checksum();
    }
    
    virtual void check() const {
        if (version() != 4) throw invalid_packet("IPv4 header version != 4");
        if (header_length_qwords() > IPV4_MAX_HEADER_LENGTH_QWORDS || header_length_qwords() < IPV4_MIN_HEADER_LENGTH_QWORDS) throw invalid_packet("Header length");
        if (calculate_checksum() != 0) {
            std::cerr << *this;
            throw invalid_packet("Checksum");
            
        }
    }
    virtual std::unique_ptr<PacketHeader> recalculate_next_header() const;
    
    void build(const IPv4Address src_ip, const IPv4Address dest_ip, const uint16_t data_size, const IPPROTO::IPPROTO next_protocol) {
        version(4);
        header_length_bytes(20);
        flags_frag_offset = 0;
        ipid = 0;
        dscp_ecn = 0;
        ttl = 128;
        source = src_ip;
        dest = dest_ip;
        protocol = next_protocol;
        size = data_size;
        update_checksum();
    }
};

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

#endif /* PacketHeaderIPv4_h */
