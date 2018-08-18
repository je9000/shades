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
    inline void resize_qwords(size_t new_size) {
        if (new_size + TCP_MIN_HEADER_LENGTH_QWORDS > TCP_MAX_HEADER_LENGTH_QWORDS) throw std::out_of_range("Invalid options size");
        qwords = new_size;
    }
    
    inline void resize_bytes(size_t new_size) {
        uint_fast8_t qw = new_size / 4;
        if (new_size % 4) qw++;
        resize_qwords(qw);
    }
    
    inline size_t size_in_bytes() {
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
    
    inline uint_fast8_t data_offset() const {
        return data_offset_and_ns() >> 4;
    }

    inline void data_offset(uint_fast8_t o) {
        if (o < TCP_MIN_HEADER_LENGTH_QWORDS || o > TCP_MAX_HEADER_LENGTH_QWORDS) throw std::out_of_range("TCP data offset invalid");
        data_offset_and_ns = (data_offset_and_ns() & 0b1111) | ((o & 0b1111) << 4);
    }
    
    inline uint_fast8_t data_offset_bytes() const {
        return data_offset() * 4;
    }
    
    void data_offset_bytes(uint_fast8_t b) {
        uint_fast8_t qwords = b / 4;
        if (b % 4) qwords++;
        return data_offset(qwords);
    }

    inline uint_fast8_t reserved() const {
        return (data_offset_and_ns() >> 1) & 0b111;
    }
    
    inline void reserved(uint_fast8_t r) {
        data_offset_and_ns = (data_offset_and_ns() & 0b11110001) | ((r & 0b111) << 3);
    }
    
    inline bool ns() const {
        return data_offset_and_ns.get_bit(0);
    }
    
    inline void ns(bool r) {
        data_offset_and_ns.set_bit(0, r);
    }
    
    // Flags
    inline bool cwr() const { return flags.get_bit(7); }
    inline void cwr(bool r) { flags.set_bit(7, r); }
    
    inline bool ece() const { return flags.get_bit(6); }
    inline void ece(bool r) { flags.set_bit(6, r); }
    
    inline bool urg() const { return flags.get_bit(5); }
    inline void urg(bool r) { flags.set_bit(5, r); }
    
    inline bool ack() const { return flags.get_bit(4); }
    inline void ack(bool r) { flags.set_bit(4, r); }
    
    inline bool psh() const { return flags.get_bit(3); }
    inline void psh(bool r) { flags.set_bit(3, r); }
    
    inline bool rst() const { return flags.get_bit(2); }
    inline void rst(bool r) { flags.set_bit(2, r); }
    
    inline bool syn() const { return flags.get_bit(1); }
    inline void syn(bool r) { flags.set_bit(1, r); }
    
    inline bool fin() const { return flags.get_bit(0); }
    inline void fin(bool r) { flags.set_bit(60, r); }
    // End flags
    
    inline size_t header_size() const {
        return data_offset_bytes();
    }
    
    uint16_t calculate_checksum() const;
    
    void update_checksum();
    
    void check() const;
};

#endif /* PacketHeaderTCP_h */
