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
    
    inline PacketBufferOffset next_header_offset() {
        return PacketBufferOffset(pbo, header_size());
    }
    
    inline const PacketBufferOffset next_header_offset() const {
        return PacketBufferOffset(pbo, header_size());
    }
    
    inline PacketHeader *previous_header() const {
        throw std::logic_error("Unimplemented");
    }
    
    inline PacketHeader *next_header() const {
        throw std::logic_error("Unimplemented");
    }
    
    inline PacketBuffer &backing_buffer() const {
        return pbo.backing_buffer();
    }
    
    inline size_t backing_buffer_offset() const {
        return pbo.backing_buffer_offset();
    }

    // Note! Only copies the one header, not the data or following headers!
    inline void copy_from(const PacketHeader &source_ph) {
        pbo.copy_from(source_ph.pbo, header_size());
    }
};

#endif /* PacketHeader_h */
