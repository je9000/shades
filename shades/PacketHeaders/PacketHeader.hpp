#ifndef PacketHeader_h
#define PacketHeader_h

#include <stdexcept>
#include <ostream>
#include <memory>

#include "PacketBuffer.hpp"

class invalid_packet : std::runtime_error {
public:
    invalid_packet(const char *what) : std::runtime_error(what) {}
};

class PacketHeader {
protected:
    virtual void print(std::ostream &) const = 0;
    PacketBufferOffset pbo;
    friend class NextHeader;
    template <size_t> friend class PacketBufferOffsetTypeBase;
    template <size_t, class> friend class BufferOffsetType;
public:
    virtual ~PacketHeader() {}
    PacketHeader(PacketBufferOffset source_pbo) : pbo(source_pbo) {}
    PacketHeader(const PacketHeader &p) = delete; // Copy the underlying PacketBuffer instead.
    friend std::ostream &operator<<(std::ostream &, const PacketHeader &);
    
    virtual size_t header_size() const = 0;
    virtual std::unique_ptr<PacketHeader> recalculate_next_header() const;
    
    PacketBufferOffset next_header_offset() {
        return PacketBufferOffset(pbo, header_size());
    }
    
    const PacketBufferOffset next_header_offset() const {
        return PacketBufferOffset(pbo, header_size());
    }
    
    PacketHeader *previous_header() const {
        throw std::logic_error("Unimplemented");
    }
    
    PacketHeader *next_header() const {
        throw std::logic_error("Unimplemented");
    }
    
    PacketBuffer &backing_buffer() const {
        return pbo.backing_buffer();
    }
    
    size_t backing_buffer_offset() const {
        return pbo.backing_buffer_offset();
    }
    
    // Note! Only copies the one header, not the data or following headers!
    void copy_header_to(PacketHeader &dest_ph) const {
        dest_ph.pbo.copy_from(pbo, header_size());
    }
    
    virtual void check() const = 0;
};

std::ostream &operator<<(std::ostream &os, const PacketHeader &ph) {
    ph.print(os);
    return os;
}

#endif /* PacketHeader_h */
