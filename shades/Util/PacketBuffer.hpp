#ifndef PacketBuffer_h
#define PacketBuffer_h

#include <exception>
#include <vector>
#include <memory>

#include <string.h>

#include "HexDump.hpp"

#ifndef MAX_FRAME_SIZE
#define MAX_FRAME_SIZE 1522
#endif

#define MAX_SANE_FRAME_SIZE 1024*1024*10

#ifndef RESERVED_HEADER_SPACE
#define RESERVED_HEADER_SPACE 64
#endif

static_assert(RESERVED_HEADER_SPACE < MAX_FRAME_SIZE, "RESERVED_HEADER_SPACE >= MAX_FRAME_SIZE");
static_assert(MAX_FRAME_SIZE <= MAX_SANE_FRAME_SIZE, "MAX_FRAME_SIZE > MAX_SANE_FRAME_SIZE");

class PacketBufferOffset;

class PacketBuffer {
protected:
    friend PacketBufferOffset;
    size_t reserved_header_space = RESERVED_HEADER_SPACE;
public:
    enum HEADER_TYPE {
        HEADER_UNKNOWN,
        HEADER_ETHERNET,
        HEADER_IPV4,
        HEADER_IPV6,
    };

    // This is valid when we receive a packet, but not necessarily when sending.
    HEADER_TYPE header_type = HEADER_UNKNOWN;
    size_t packet_id = 0;
    
    PacketBuffer();
    PacketBuffer(size_t);
    PacketBuffer(const PacketBufferOffset &);

    PacketBuffer(const PacketBuffer &);
    PacketBuffer(PacketBuffer &&);

    void reset_size(size_t = MAX_FRAME_SIZE);
    size_t size() const;
    
    unsigned char *data();
    unsigned char &at(size_t n);

    unsigned char *reserved_data();
    size_t get_reserved_space() const;
    void reset_reserved_space();
    
    // These are bad names.
    void take_reserved_space(size_t);
    void put_reserved_space(size_t);

    void set_valid_size(size_t);
    
    void copy_from(const unsigned char *, size_t, HEADER_TYPE);

    PacketBufferOffset offset(size_t);

    std::vector<unsigned char> buffer;
};

class PacketBufferOffset {
private:
    PacketBuffer &pb;
    mutable size_t offset;
    mutable size_t original_reserved_header_space;
public:
    PacketBufferOffset(PacketBuffer &base_pb, size_t next_offset) : pb(base_pb), offset(next_offset), original_reserved_header_space(base_pb.reserved_header_space) {
        if (next_offset >= pb.size()) throw std::out_of_range("Offset too large!");
    }
    
    PacketBufferOffset(PacketBufferOffset &pbo, size_t next_offset) : pb(pbo.pb), offset(next_offset + pbo.offset), original_reserved_header_space(pbo.pb.reserved_header_space) {
        if (next_offset >= pb.size()) throw std::out_of_range("Offset too large!");
    }
    
    PacketBufferOffset(const PacketBufferOffset &pbo, size_t next_offset) : pb(pbo.pb), offset(next_offset + pbo.offset), original_reserved_header_space(pbo.pb.reserved_header_space) {
        if (next_offset >= pb.size()) throw std::out_of_range("Offset too large!");
    }
    
    //PacketBufferOffset(PacketBufferOffset &pbo) : pbo(pbo.pbo), offset(0) {}
    PacketBufferOffset(PacketBuffer &base_pb) : pb(base_pb), offset(0), original_reserved_header_space(base_pb.reserved_header_space) {}
    
    friend std::ostream& operator<<(std::ostream &, const PacketBufferOffset &);
    
    void adjust_offset() const;
    
    size_t size() const;
    
    unsigned char *data() const;
    
    unsigned char *at(size_t o2) const;
    
    PacketBuffer &backing_buffer() const;
    
    size_t backing_buffer_offset() const;

    void copy_from(const PacketBufferOffset &, size_t = 0, size_t = 0);
    void copy_from(const unsigned char *, size_t, size_t = 0);
};

#endif /* PacketBuffer_h */
