#ifndef PacketHeaderUnknown_h
#define PacketHeaderUnknown_h

#include "PacketHeader.hpp"
#include "PacketBuffer.hpp"

class PacketHeaderUnknown : public PacketHeader {
public:
    PacketHeaderUnknown(PacketBufferOffset source_pbo) : PacketHeader(source_pbo) {}
    inline void print(std::ostream &os) const {
        os << " UNKNOWN HEADER\n";
    }
    inline size_t header_size() const {
        throw std::runtime_error("Can't get size for unknown header");
    }
    inline void check() const {}
};

#endif /* PacketHeaderUnknown_h */
