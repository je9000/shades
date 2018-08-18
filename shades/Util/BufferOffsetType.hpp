#ifndef BufferOffsetType_h
#define BufferOffsetType_h

#include <exception>
#include <vector>

#include <string.h>
#include <netinet/in.h>

#include "PacketHeader.hpp"
#include "PacketBuffer.hpp"

template <size_t O>
class PacketBufferOffsetTypeBase {
protected:
    PacketHeader &ph;
    inline void check_offset(const size_t s) const {
        size_t pos = O + s;
        if (pos < O || pos > ph.pbo.size()) throw std::out_of_range("offset too large for buffer");
    }
public:
    PacketBufferOffsetTypeBase(PacketHeader &source_ph) : ph(source_ph) {}
};

template <size_t O, class T>
class BufferOffsetType : PacketBufferOffsetTypeBase<O> {
public:
    BufferOffsetType(PacketHeader &source_ph) : PacketBufferOffsetTypeBase<O>(source_ph) {}
    T operator()() const {
        T r;
        this->check_offset(sizeof(r));
        memcpy(r.data(), this->ph.pbo.at(O), sizeof(r));
        return r;
    }
    void operator=(const T &src) {
        this->check_offset(sizeof(src));
        memcpy(this->ph.pbo.at(O), &src, sizeof(src));
    }
};

/*
template <size_t O>
class BufferOffsetType<O, char *> : PacketBufferOffsetTypeBase<O> {
public:
    BufferOffsetType(PacketBufferOffset &source_pbo) : PacketBufferOffsetTypeBase<O>(source_pbo) {}
    void operator()(char *dest, size_t dest_size) const {
        this->check_offset(dest_size);
        memcpy(dest, this->pbo.at(O), dest_size);
    }
    void operator=(const char *src, size_t src_size) {
        this->check_offset(src_size);
        memcpy(this->pbo.at(O), src, src_size);
    }
};
*/

template <size_t O, class V>
class BufferOffsetType<O, std::vector<V>> : PacketBufferOffsetTypeBase<O> {
public:
    BufferOffsetType(PacketHeader &source_ph) : PacketBufferOffsetTypeBase<O>(source_ph) {}
    void operator()(std::vector<V> &v, size_t read_amount) const {
        this->check_offset(read_amount);
        v.resize(read_amount);
        memcpy(v.data(), this->ph.pbo.at(O), read_amount);
    }
    void operator=(const std::vector<V> &v) {
        this->check_offset(v.size());
        memcpy(this->ph.pbo.at(O), v.data(), v.size());
    }
};

template <size_t O>
class BufferOffsetType<O, uint16_t> : PacketBufferOffsetTypeBase<O> {
public:
    BufferOffsetType(PacketHeader &source_ph) : PacketBufferOffsetTypeBase<O>(source_ph) {}
    uint16_t operator()() const {
        uint16_t r;
        this->check_offset(sizeof(r));
        memcpy(&r, this->ph.pbo.at(O), sizeof(r));
        return ntohs(r);
    }
    void operator=(uint16_t src) {
        this->check_offset(sizeof(src));
        src = htons(src);
        memcpy(this->ph.pbo.at(O), &src, sizeof(src));
    }
};

template <size_t O>
class BufferOffsetType<O, uint32_t> : PacketBufferOffsetTypeBase<O> {
public:
    BufferOffsetType(PacketHeader &source_ph) : PacketBufferOffsetTypeBase<O>(source_ph) {}
    uint32_t operator()() const {
        uint32_t r;
        this->check_offset(sizeof(r));
        memcpy(&r, this->ph.pbo.at(O), sizeof(r));
        return ntohl(r);
    }
    void operator=(uint32_t src) {
        this->check_offset(sizeof(src));
        src = htonl(src);
        memcpy(this->ph.pbo.at(O), &src, sizeof(src));
    }
};

template <size_t O>
class BufferOffsetType<O, uint8_t> : PacketBufferOffsetTypeBase<O> {
public:
    BufferOffsetType(PacketHeader &source_ph) : PacketBufferOffsetTypeBase<O>(source_ph) {}
    uint8_t operator()() const {
        this->check_offset(sizeof(uint8_t));
        return *this->ph.pbo.at(O);
    }
    void operator=(uint8_t src) {
        this->check_offset(sizeof(uint8_t));
        *this->ph.pbo.at(O) = src;
    }

    bool get_bit(size_t bit) const {
        if (bit >= sizeof(uint8_t) * 8) throw std::out_of_range("Bit out of range");
        return ((*this)() >> bit) & 0x1;
    }

    void set_bit(size_t bit, bool val) {
        if (bit >= sizeof(uint8_t) * 8) throw std::out_of_range("Bit out of range");
        *this = ((*this)() & (~(1 << bit))) | (val << bit); // bool is guaranteed to only ever be 1 or 0, right?
    }
};

#endif /* BufferOffsetType_h */
