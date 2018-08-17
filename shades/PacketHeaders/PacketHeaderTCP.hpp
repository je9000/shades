#ifndef PacketHeaderTCP_h
#define PacketHeaderTCP_h

#include "InetChecksum.hpp"
#include "PacketHeader.hpp"
#include "PacketBuffer.hpp"
#include "BufferOffsetType.hpp"

static const unsigned int TCP_MAX_HEADER_LENGTH_QWORDS = 15;
static const unsigned int TCP_MIN_HEADER_LENGTH_QWORDS = 5;

/*
class NetworkFlowIPv4TCP {
public:
    NetworkFlowIPv4 ips;
    uint16_t source_port;
    uint16_t dest_port;
    
    bool operator==(const NetworkFlowIPv4TCP &other) {
        return (
                ips == other.ips &&
                source_port == other.source_port && dest_port == other.dest_port
                );
    }
};

namespace std {
    template <>
    struct hash<NetworkFlowIPv4TCP> {
        std::size_t operator()(const NetworkFlowIPv4TCP& nfu) const {
            if (sizeof(std::size_t) >= 8) {
                return ((static_cast<std::size_t>(nfu.source_ip.ip_int) ^ nfu.dest_ip.ip_int) << 32) | (nfu.source_port << 16) | nfu.dest_port;
            } else {
                return nfu.source_ip.ip_int ^ nfu.dest_ip.ip_int ^ nfu.source_port ^ nfu.dest_port;
            }
        }
    };
}
*/

class TCPOptions {
private:
    size_t qwords = 0;
public:
    void resize_qwords(size_t new_size) {
        if (new_size + TCP_MIN_HEADER_LENGTH_QWORDS > TCP_MAX_HEADER_LENGTH_QWORDS) throw std::out_of_range("Invalid options size");
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

class PacketHeaderTCP : public PacketHeader {
public:
    BufferOffsetType<0, uint16_t> source_port;
    BufferOffsetType<2, uint16_t> dest_port;
    BufferOffsetType<4, uint32_t> seq_num;
    BufferOffsetType<8, uint32_t> ack_num;
    BufferOffsetType<12, uint8_t> data_offset_and_ns;
    BufferOffsetType<13, uint8_t> flags;
    BufferOffsetType<14, uint16_t> window_size;
    BufferOffsetType<16, InetChecksum> checksum;
    BufferOffsetType<18, uint16_t> urg_ptr;
    TCPOptions options;
    
    PacketHeaderTCP(PacketBufferOffset source_pbo) :
        PacketHeader(source_pbo),
        source_port(*this),
        dest_port(*this),
        seq_num(*this),
        ack_num(*this),
        data_offset_and_ns(*this),
        flags(*this),
        window_size(*this),
        checksum(*this),
        urg_ptr(*this)
    {}
    
    void print(std::ostream &) const;
    
    uint_fast8_t data_offset() const {
        return data_offset_and_ns() >> 4;
    }

    void data_offset(uint_fast8_t o) {
        if (o < TCP_MIN_HEADER_LENGTH_QWORDS || o > TCP_MAX_HEADER_LENGTH_QWORDS) throw std::out_of_range("TCP data offset invalid");
        data_offset_and_ns = (data_offset_and_ns() & 0b1111) | ((o & 0b1111) << 4);
    }
    
    uint_fast8_t data_offset_bytes() const {
        return data_offset() * 4;
    }
    
    void data_offset_bytes(uint_fast8_t b) {
        uint_fast8_t qwords = b / 4;
        if (b % 4) qwords++;
        return data_offset(qwords);
    }

    uint_fast8_t reserved() const {
        return (data_offset_and_ns() >> 1) & 0b111;
    }
    
    void reserved(uint_fast8_t r) {
        data_offset_and_ns = (data_offset_and_ns() & 0b11110001) | ((r & 0b111) << 3);
    }
    
    bool ns() const {
        return data_offset_and_ns.get_bit(0);
    }
    
    void ns(bool r) {
        data_offset_and_ns.set_bit(0, r);
    }
    
    // Flags
    bool cwr() const { return flags.get_bit(7); }
    void cwr(bool r) { flags.set_bit(7, r); }
    
    bool ece() const { return flags.get_bit(6); }
    void ece(bool r) { flags.set_bit(6, r); }
    
    bool urg() const { return flags.get_bit(5); }
    void urg(bool r) { flags.set_bit(5, r); }
    
    bool ack() const { return flags.get_bit(4); }
    void ack(bool r) { flags.set_bit(4, r); }
    
    bool psh() const { return flags.get_bit(3); }
    void psh(bool r) { flags.set_bit(3, r); }
    
    bool rst() const { return flags.get_bit(2); }
    void rst(bool r) { flags.set_bit(2, r); }
    
    bool syn() const { return flags.get_bit(1); }
    void syn(bool r) { flags.set_bit(1, r); }
    
    bool fin() const { return flags.get_bit(0); }
    void fin(bool r) { flags.set_bit(60, r); }
    // End flags
    
    size_t header_size() const {
        return data_offset_bytes();
    }
    
    uint16_t calculate_checksum() const {
        InetChecksumCalculator icc;
        icc.checksum_update(pbo.data(), pbo.size());
        return icc.checksum_finalize();
    }
    
    void update_checksum() {
        checksum = 0;
        checksum = calculate_checksum();
    }
    
    virtual void check() const {
        if (calculate_checksum() != 0) throw invalid_packet("Checksum");
        if (data_offset() < TCP_MIN_HEADER_LENGTH_QWORDS || data_offset() > TCP_MAX_HEADER_LENGTH_QWORDS) throw std::out_of_range("TCP data offset invalid");
        if (reserved() != 0) throw invalid_packet("TCP reserved bits invalid");
        if (syn() && (fin() || rst())) throw invalid_packet("SYN and FIN or RST bits set");
    }
};

void PacketHeaderTCP::print(std::ostream &os) const {
    os << "TCP packet:\n";
    os << " Source Port: " << source_port() << "\n";
    os << " Dest Port: " << dest_port() << "\n";
    os << " Sequence Number: " << seq_num() << "\n";
    os << " Ack Number: " << ack_num() << "\n";
    os << " Data Offset: " << data_offset() << " (" << data_offset_bytes() << " bytes)\n";
    os << " Reserved: " << reserved() << "\n";
    os << " Flags: " << flags() << "\n";
    os << "  NS: " << ns() << "\n";
    os << "  CWR: " << cwr() << "\n";
    os << "  ECE: " << ece() << "\n";
    os << "  URG: " << urg() << "\n";
    os << "  ACK: " << ack() << "\n";
    os << "  PSH: " << psh() << "\n";
    os << "  RST: " << rst() << "\n";
    os << "  SYN: " << syn() << "\n";
    os << "  FIN: " << fin() << "\n";
    os << " Window Size: " << window_size() << "\n";
    os << " Checksum: " << checksum() << "\n";
    os << " Urgent Pointer: " << urg_ptr() << "\n";
    //os << " Options: " << options << "\n";
}

#endif /* PacketHeaderTCP_h */
