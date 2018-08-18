#ifndef PacketHeaderICMP_h
#define PacketHeaderICMP_h

#include "HexDump.hpp"
#include "InetChecksum.hpp"
#include "PacketHeader.hpp"
#include "PacketBuffer.hpp"
#include "BufferOffsetType.hpp"

namespace ICMP {
    enum ICMP {
        ECHOREPLY = 0,
        UNREACH = 3,
        UNREACH_NET = 0,
        UNREACH_HOST = 1,
        UNREACH_PROTOCOL = 2,
        UNREACH_PORT = 3,
        UNREACH_NEEDFRAG = 4,
        UNREACH_SRCFAIL = 5,
        UNREACH_NET_UNKNOWN = 6,
        UNREACH_HOST_UNKNOWN = 7,
        UNREACH_ISOLATED = 8,
        UNREACH_NET_PROHIB = 9,
        UNREACH_HOST_PROHIB = 10,
        UNREACH_TOSNET = 11,
        UNREACH_TOSHOST = 12,
        UNREACH_FILTER_PROHIB = 13,
        UNREACH_HOST_PRECEDENCE = 14,
        UNREACH_PRECEDENCE_CUTOFF = 15,
        SOURCEQUENCH = 4,
        REDIRECT = 5,
        REDIRECT_NET = 0,
        REDIRECT_HOST = 1,
        REDIRECT_TOSNET = 2,
        REDIRECT_TOSHOST = 3,
        ALTHOSTADDR = 6,
        ECHO = 8,
        ROUTERADVERT = 9,
        ROUTERADVERT_NORMAL = 0,
        ROUTERADVERT_NOROUTE_COMMON = 16,
        ROUTERSOLICIT = 10,
        TIMXCEED = 11,
        TIMXCEED_INTRANS = 0,
        TIMXCEED_REASS = 1,
        PARAMPROB = 12,
        PARAMPROB_ERRATPTR = 0,
        PARAMPROB_OPTABSENT = 1,
        PARAMPROB_LENGTH = 2,
        TSTAMP = 13,
        TSTAMPREPLY = 14,
        IREQ = 15,
        IREQREPLY = 16,
        MASKREQ = 17,
        MASKREPLY = 18,
        TRACEROUTE = 30,
        DATACONVERR = 31,
        MOBILE_REDIRECT = 32,
        IPV6_WHEREAREYOU = 33,
        IPV6_IAMHERE = 34,
        MOBILE_REGREQUEST = 35,
        MOBILE_REGREPLY = 36,
        SKIP = 39,
        PHOTURIS = 40,
        PHOTURIS_UNKNOWN_INDEX = 1,
        PHOTURIS_AUTH_FAILED = 2,
        PHOTURIS_DECRYPT_FAILED = 3
    };
}

class PacketHeaderICMP : public PacketHeader {
public:
    BufferOffsetType<0, uint8_t> type;
    BufferOffsetType<1, uint8_t> code;
    BufferOffsetType<2, InetChecksum> checksum;
    
    PacketHeaderICMP(PacketBufferOffset source_pbo) :
        PacketHeader(source_pbo),
        type(*this),
        code(*this),
        checksum(*this)
    {}
    
    void print(std::ostream &) const;
    
    inline size_t header_size() const {
        return 4;
    }
    
    uint16_t calculate_checksum() const;
    
    void update_checksum();
    
    void check() const;
};

// Echo
class PacketHeaderICMPEcho : public PacketHeader {
public:
    BufferOffsetType<0, uint16_t> ident;
    BufferOffsetType<2, uint16_t> seq;
    
    PacketHeaderICMPEcho(PacketBufferOffset source_pbo) :
        PacketHeader(source_pbo),
        ident(*this),
        seq(*this)
    {}
    
    void check() const {};
    
    void print(std::ostream &) const;
    
    inline size_t header_size() const {
        return 4;
    }
};

#endif /* PacketHeaderICMP_h */
