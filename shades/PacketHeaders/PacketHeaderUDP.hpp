#ifndef PacketHeaderUDP_h
#define PacketHeaderUDP_h

//#include <unordered_map>

#include "InetChecksum.hpp"
#include "PacketHeader.hpp"
#include "PacketBuffer.hpp"
#include "BufferOffsetType.hpp"
#include "PacketHeaderIPv4.hpp"

/*
class NetworkFlowIPv4UDP {
public:
    NetworkFlowIPv4 ips;
    uint16_t source_port;
    uint16_t dest_port;
    
    bool operator==(const NetworkFlowIPv4UDP &other) {
        return (
                ips == other.ips && &&
                source_port == other.source_port && dest_port == other.dest_port
                );
    }
};

namespace std {
    template <>
    struct hash<NetworkFlowIPv4UDP> {
        std::size_t operator()(const NetworkFlowIPv4UDP& nfu) const {
            if (sizeof(std::size_t) >= 8) {
                return ((static_cast<std::size_t>(nfu.source_ip.ip_int) ^ nfu.dest_ip.ip_int) << 32) | (nfu.source_port << 16) | nfu.dest_port;
            } else {
                return nfu.source_ip.ip_int ^ nfu.dest_ip.ip_int ^ nfu.source_port ^ nfu.dest_port;
            }
        }
    };
}

typedef std::unordered_map<const NetworkFlowIPv4UDP, void *> NetworkFlowsIPv4UDP;
*/

class PacketHeaderUDP : public PacketHeader {
private:
    bool checksum_matters = true;
public:
    BufferOffsetType<0, uint8_t> source_port;
    BufferOffsetType<1, uint8_t> dest_port;
    BufferOffsetType<2, uint16_t> length;
    BufferOffsetType<4, InetChecksum> checksum;
    
    PacketHeaderUDP(PacketBufferOffset source_pbo) : PacketHeaderUDP(source_pbo, nullptr) {}
    PacketHeaderUDP(PacketBufferOffset source_pbo, PacketHeader *my_parent) :
        PacketHeader(source_pbo),
        source_port(*this),
        dest_port(*this),
        length(*this),
        checksum(*this)
    {
        if (my_parent && dynamic_cast<PacketHeaderIPv4 *>(my_parent)) checksum_matters = false;
    }
    
    void print(std::ostream &) const ;
    
    size_t header_size() const {
        return 8;
    }
    
    uint16_t calculate_checksum() const {
        InetChecksumCalculator icc;
        icc.checksum_update(pbo.data(), pbo.size());
        return icc.checksum_finalize();
    }
    
    void update_checksum() {
        checksum = 0;
        checksum = calculate_checksum();
    }
    
    virtual void check() const {
        // Checksum is optional in IPv4 and mandatory in IPv6.
        if ((checksum_matters || checksum() != 0) && (calculate_checksum() != 0)) throw invalid_packet("Checksum");
    }
};

void PacketHeaderUDP::print(std::ostream &os) const {
    os << "UDP packet:\n";
    os << " Source Port: " << source_port() << "\n";
    os << " Desk Port: " << dest_port() << "\n";
    os << " Length: " << length() << "\n";
    os << " Checksum: " << checksum() << "\n";
}

#endif /* PacketHeaderUDP_h */
