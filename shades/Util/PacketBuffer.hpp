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

class PacketBufferOffset;

enum PacketBufferHeaderType {
    HEADER_UNKNOWN,
    HEADER_ETHERNET,
    HEADER_IPV4,
    HEADER_IPV6,
};

class PacketBuffer {
private:
    PacketBufferHeaderType header_type = HEADER_UNKNOWN;
    size_t reserved_header_space = 16;
public:
    PacketBuffer() {
        buffer.resize(MAX_FRAME_SIZE + reserved_header_space);
    }
    
    PacketBuffer(size_t x) {
        buffer.resize(x + reserved_header_space);
    }

    size_t size() const {
        return buffer.size() - reserved_header_space;
    }
    
    unsigned char *data() {
        return &buffer.at(reserved_header_space);
    }
    
    unsigned char &at(size_t n) {
        return buffer.at(reserved_header_space + n);
    }
    
    unsigned char *reserved_data() {
        return buffer.data();
    }
    
    size_t reserved_size() const {
        return reserved_header_space;
    }
    
    void set_valid_size(size_t len) {
        size_t real_len = len + reserved_header_space;
        if (real_len < len || len + reserved_header_space > MAX_SANE_FRAME_SIZE) throw std::out_of_range("> buffer.max_size");
        buffer.resize(real_len);
    }
    
    void copy_from(const unsigned char *src, size_t len, PacketBufferHeaderType ht) {
        if (!src) throw std::runtime_error("Invalid data");
        size_t real_len = len + reserved_header_space;
        if (real_len < len || real_len > MAX_SANE_FRAME_SIZE) throw std::out_of_range("> buffer.max_size");
        buffer.resize(real_len);
        if (len) memcpy(data(), src, len);
        header_type = ht;
    }
    
    PacketBufferHeaderType get_header_type() const { return header_type; }
    
    PacketBufferOffset offset(size_t);

    std::vector<unsigned char> buffer;
};

std::ostream& operator<<(std::ostream &os, const PacketBuffer &pb)
{
    os << "PacketBuffer (" << pb.size() << " bytes, +" << pb.reserved_size() << " reserved):\n";
    os << HexDump<decltype(pb.buffer)>(pb.buffer) << '\n';
    return os;
}

class PacketBufferOffset {
private:
    PacketBuffer &pb;
    size_t offset;
public:
    PacketBufferOffset(PacketBuffer &pb, size_t next_offset) : pb(pb), offset(next_offset) {
        if (next_offset >= pb.size()) throw std::out_of_range("Offset too large!");
    }
    
    PacketBufferOffset(PacketBufferOffset &pbo, size_t next_offset) : pb(pbo.pb), offset(next_offset + pbo.offset) {
        if (next_offset >= pb.size()) throw std::out_of_range("Offset too large!");
    }
    
    PacketBufferOffset(const PacketBufferOffset &pbo, size_t next_offset) : pb(pbo.pb), offset(next_offset + pbo.offset) {
        if (next_offset >= pb.size()) throw std::out_of_range("Offset too large!");
    }
    
    //PacketBufferOffset(PacketBufferOffset &pbo) : pbo(pbo.pbo), offset(0) {}
    PacketBufferOffset(PacketBuffer &pb) : pb(pb), offset(0) {}
    
    size_t size() const {
        return pb.size() - offset;
    }
    
    unsigned char *data() const {
        return &pb.at(offset);
    }
    
    unsigned char *at(size_t o2) const {
        size_t pos = offset + o2;
        if (pos < offset) throw std::length_error("offset too large");
        return &pb.at(pos);
    }
    
    PacketBuffer &backing_buffer() const {
        return pb;
    }
    
    size_t backing_buffer_offset() const {
        return offset;
    }

    void copy_from(const PacketBufferOffset &source_pbo, size_t len, size_t dest_offset = 0) {
        size_t new_end_pos = len + dest_offset;
        if (new_end_pos < len || new_end_pos > size()) throw std::length_error("not enough room in buffer");
        memcpy(at(dest_offset), source_pbo.data(), len);
    }
};

std::ostream& operator<<(std::ostream& os, const PacketBufferOffset& pbo) {
    os << "PacketBufferOffset (" << pbo.size() << " bytes):\n";
    HexDumpCharHelper hdch(pbo.data(), pbo.size());
    os << " Data:\n" << HexDump<HexDumpCharHelper>(hdch, 80) << "\n";
    return os;
}

PacketBufferOffset PacketBuffer::offset(size_t o) {
    return PacketBufferOffset(*this, o + reserved_header_space);
}

#endif /* PacketBuffer_h */
