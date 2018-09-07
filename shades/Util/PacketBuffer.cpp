#include "PacketBuffer.hpp"
#include "HexDump.hpp"

PacketBuffer::PacketBuffer() {
    reset_size();
}

PacketBuffer::PacketBuffer(size_t x) {
    reset_size(x);
}

void PacketBuffer::reset_size(size_t x) {
    if (x + reserved_header_space < buffer.size()) reset_reserved_space();
    buffer.resize(x + reserved_header_space);
}

size_t PacketBuffer::size() const {
    return buffer.size() - reserved_header_space;
}

unsigned char *PacketBuffer::data() {
    return &buffer.at(reserved_header_space);
}

unsigned char &PacketBuffer::at(size_t n) {
    return buffer.at(reserved_header_space + n);
}

unsigned char *PacketBuffer::reserved_data() {
    return buffer.data();
}

size_t PacketBuffer::get_reserved_space() const {
    return reserved_header_space;
}

void PacketBuffer::reset_reserved_space() {
    reserved_header_space = RESERVED_HEADER_SPACE;
}

void PacketBuffer::take_reserved_space(size_t amount) {
    if (amount > reserved_header_space) throw std::out_of_range("Not enough reserved space");
    reserved_header_space -= amount;
}

void PacketBuffer::put_reserved_space(size_t amount) {
    size_t new_reserved_space = reserved_header_space + amount;
    if (new_reserved_space < reserved_header_space || new_reserved_space >= buffer.size()) throw std::out_of_range("Not enough space");
    reserved_header_space = new_reserved_space;
}

void PacketBuffer::set_valid_size(size_t len) {
    size_t real_len = len + reserved_header_space;
    if (real_len < len || len + reserved_header_space > MAX_SANE_FRAME_SIZE) throw std::out_of_range("> buffer.max_size");
    buffer.resize(real_len);
}

void PacketBuffer::copy_from(const unsigned char *src, size_t len, HEADER_TYPE ht) {
    if (!src || !len) throw std::runtime_error("Invalid arguments");
    reset_reserved_space();
    size_t real_len = len + reserved_header_space;
    if (real_len < len || real_len > MAX_SANE_FRAME_SIZE) throw std::out_of_range("> MAX_SANE_FRAME_SIZE");
    buffer.resize(len + reserved_header_space);
    memcpy(data(), src, len);
    header_type = ht;
}

PacketBufferOffset PacketBuffer::offset(size_t o) {
    return PacketBufferOffset(*this, o + reserved_header_space);
}

std::ostream& operator<<(std::ostream &os, const PacketBuffer &pb) {
    os << "PacketBuffer (" << pb.size() << " bytes, +" << pb.get_reserved_space() << " reserved):\n";
    os << HexDump<decltype(pb.buffer)>(pb.buffer) << '\n';
    return os;
}

//PacketBufferOffset
void PacketBufferOffset::adjust_offset() const {
    ssize_t diff = original_reserved_header_space - pb.reserved_header_space;
    if (diff == 0) return;
    if (static_cast<ssize_t>(offset) + diff < 0) throw std::out_of_range("reserved size size change puts this into reserved space");
    if (offset + diff > pb.buffer.size()) throw std::out_of_range("reserved size changed too much");
    original_reserved_header_space = pb.reserved_header_space;
    offset += diff;
}

size_t PacketBufferOffset::size() const {
    adjust_offset();
    return pb.size() - offset;
}

unsigned char *PacketBufferOffset::data() const {
    adjust_offset();
    return &pb.at(offset);
}

unsigned char *PacketBufferOffset::at(size_t o2) const {
    adjust_offset();
    size_t pos = offset + o2;
    if (pos < offset) throw std::length_error("offset too large");
    return &pb.at(pos);
}

PacketBuffer &PacketBufferOffset::backing_buffer() const {
    return pb;
}

size_t PacketBufferOffset::backing_buffer_offset() const {
    adjust_offset();
    return offset;
}

void PacketBufferOffset::copy_from(const PacketBufferOffset &source_pbo, size_t len, size_t dest_offset) {
    if (len == 0) len = source_pbo.size();
    size_t new_end_pos = len + dest_offset;
    if (new_end_pos < len || new_end_pos > size()) throw std::length_error("not enough room in buffer");
    memcpy(at(dest_offset), source_pbo.data(), len);
}

std::ostream& operator<<(std::ostream &os, const PacketBufferOffset &pbo) {
    os << "PacketBufferOffset (" << pbo.size() << " bytes):\n";
    HexDumpCharHelper hdch(pbo.data(), pbo.size());
    os << " Data:\n" << HexDump<HexDumpCharHelper>(hdch, 80) << "\n";
    return os;
}

