#ifndef PacketHeaderTCP_h
#define PacketHeaderTCP_h

#include "InetChecksum.hpp"
#include "PacketHeader.hpp"
#include "PacketBuffer.hpp"
#include "BufferOffsetType.hpp"
#include "PacketHeaderIPv4.hpp"

static const unsigned int TCP_MAX_HEADER_LENGTH_QWORDS = 15;
static const unsigned int TCP_MIN_HEADER_LENGTH_QWORDS = 5;
static const unsigned int TCP_DEFAULT_WINDOW_SIZE = 65535;

static const unsigned int TCP_FLAG_FIN = 1 << 0;
static const unsigned int TCP_FLAG_SYN = 1 << 1;
static const unsigned int TCP_FLAG_RST = 1 << 2;
static const unsigned int TCP_FLAG_PSH = 1 << 3;
static const unsigned int TCP_FLAG_ACK = 1 << 4;
static const unsigned int TCP_FLAG_URG = 1 << 5;
static const unsigned int TCP_FLAG_ECE = 1 << 6;
static const unsigned int TCP_FLAG_CWR = 1 << 7;

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
    inline void fin(bool r) { flags.set_bit(0, r); }
    // End flags
    
    inline size_t header_size() const { return data_offset_bytes(); }
    
    static size_t minimum_header_size() { return TCP_MIN_HEADER_LENGTH_QWORDS * 4;}
    
    uint16_t calculate_checksum(const IPv4Address &, const IPv4Address &) const;
    void update_checksum(const IPv4Address &, const IPv4Address &);
    //void update_checksum(const IPv6Address &, const IPv6Address &); TODO
    
    void build(uint16_t, uint16_t, uint32_t);
    void check(const IPv4Address &, const IPv4Address &) const;
};

#endif /* PacketHeaderTCP_h */
