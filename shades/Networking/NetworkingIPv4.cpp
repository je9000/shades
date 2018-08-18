#include "Networking.hpp"
#include "NetworkingIPv4.hpp"
#include "PacketHeaders.hpp"

void NetworkingIPv4::send(const IPv4Address &dest, const IPPROTO::IPPROTO proto, const PacketBufferOffset &pbo) {
    PacketBuffer pb = pbo.backing_buffer();
    pb.unreserve_space(20);
    PacketHeaderIPv4 ipv4(pb.offset(0));
    
    ipv4.source = networking.my_ip;
    ipv4.dest = dest;
    ipv4.protocol = proto;
    ipv4.update_checksum();
    
    networking.net_driver.send(pb);
}
