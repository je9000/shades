#include "PacketHeaderARP.hpp"
#include "PacketHeaderEthernet.hpp"

void PacketHeaderARP::check() const {
    if (htype() != 1 || hlen() != 6) throw invalid_packet("ARP for non-Ethernet not supported");
    if (ptype() != 0x0800 || plen() != 4) throw invalid_packet("ARP for non-IPv4 not supported");
    if (oper() != ARP::REQUEST && oper() != ARP::REPLY) throw invalid_packet("Invalid ARP OPER");
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
