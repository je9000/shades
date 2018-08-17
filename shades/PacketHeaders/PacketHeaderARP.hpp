#ifndef PacketHeaderARP_h
#define PacketHeaderARP_h

#include "HexDump.hpp"
#include "PacketHeader.hpp"
#include "PacketBuffer.hpp"
#include "BufferOffsetType.hpp"
#include "PacketHeaderEthernet.hpp"
#include "PacketHeaderIPv4.hpp"

namespace ARP {
    enum OPER_TYPE { REQUEST = 1, REPLY = 2 };
}

class PacketHeaderARP : public PacketHeader {
public:
    BufferOffsetType<0, uint16_t> htype;
    BufferOffsetType<2, uint16_t> ptype;
    BufferOffsetType<4, uint8_t> hlen;
    BufferOffsetType<5, uint8_t> plen;
    BufferOffsetType<6, uint16_t> oper;
    
    BufferOffsetType<8, EthernetAddress> sender_mac;
    BufferOffsetType<14, IPv4Address> sender_ip;
    BufferOffsetType<18, EthernetAddress> target_mac;
    BufferOffsetType<24, IPv4Address> target_ip;
    
    PacketHeaderARP(PacketBufferOffset source_pbo) :
        PacketHeader(source_pbo),
        htype(*this),
        ptype(*this),
        hlen(*this),
        plen(*this),
        oper(*this),
        sender_mac(*this),
        sender_ip(*this),
        target_mac(*this),
        target_ip(*this)
    {}
    
    void check() const {
        if (htype() != 1 || hlen() != 6) throw invalid_packet("ARP for non-Ethernet not supported");
        if (ptype() != 0x0800 || plen() != 4) throw invalid_packet("ARP for non-IPv4 not supported");
        if (oper() != ARP::REQUEST && oper() != ARP::REPLY) throw invalid_packet("Invalid ARP OPER");
    };
    
    void print(std::ostream &) const;
    
    size_t header_size() const {
        return 28;
    }
};

void PacketHeaderARP::print(std::ostream &os) const {
    os << "ARP header:\n";
    os << " HTYPE: " << htype() << "\n";
    os << " PTYPE: " << ptype() << "\n";
    os << " HLEN: " << static_cast<unsigned>(hlen()) << "\n";
    os << " PLEN: " << static_cast<unsigned>(plen()) << "\n";
    os << " OPER: " << oper() << "\n";
    os << " Sender MAC: " << sender_mac() << "\n";
    os << " Sender IP: " << sender_ip() << "\n";
    os << " Target MAC: " << target_mac() << "\n";
    os << " Target IP: " << target_ip() << "\n";
}

#endif /* PacketHeaderARP_h */
