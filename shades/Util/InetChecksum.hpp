#ifndef InetChecksum_h
#define InetChecksum_h

#include <cstdint>
#include <arpa/inet.h>

typedef uint16_t InetChecksum;

typedef const unsigned short * __attribute__((__may_alias__)) may_alias_ushort_ptr;
typedef const unsigned char * __attribute__((__may_alias__)) may_alias_uchar_ptr;

// It might be nicer to have this be a type that is BufferOffset convertible, but I'm not sure how that API would work.

class InetChecksumCalculator {
private:
    uint32_t checksum = 0;
public:
    InetChecksum checksum_finalize() {
        uint32_t c = (checksum >> 16) + (checksum & 0xFFFF);
        c = ~(c + (c >> 16)) & 0xFFFF;
        return ntohs(c);
    }
    
    inline void checksum_update(const void *buf, size_t len) {
        may_alias_ushort_ptr words = static_cast<may_alias_ushort_ptr>(buf);
        may_alias_uchar_ptr bytes = static_cast<may_alias_uchar_ptr>(buf);
        
        for(size_t i = 0; len > 0; i++, len -= 2) {
            if (len == 1) {
                checksum += bytes[i * 2];
                break;
            }
            checksum += words[i];
        }
    }
    
    inline void reset() { checksum = 0; }
};

#endif /* InetChecksum_h */
