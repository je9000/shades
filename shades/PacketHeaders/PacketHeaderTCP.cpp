#include "PacketHeaderIPv4.hpp"
#include "PacketHeaderTCP.hpp"

uint16_t PacketHeaderTCP::calculate_checksum(const IPv4Address &srcip, const IPv4Address &destip) const {
    InetChecksumCalculator icc;
    uint32_t reserved_and_proto = htons(IPPROTO_TCP);
    //struct reserved_and_proto { uint16_t reserved; uint16_t proto; } __attribute__((packed)) reserved_and_proto = { 0, htons(IPPROTO_TCP) };
    uint32_t data_len = static_cast<uint32_t>(pbo.size());
    if (data_len != pbo.size()) throw std::out_of_range("Packet too big for TCP");
    data_len = htonl(data_len);

    icc.checksum_update(&srcip.ip_int, sizeof(srcip.ip_int));
    icc.checksum_update(&destip.ip_int, sizeof(destip.ip_int));
    icc.checksum_update(&reserved_and_proto, sizeof(reserved_and_proto));
    icc.checksum_update(&data_len, sizeof(data_len));
    icc.checksum_update(pbo.data(), pbo.size());
    return icc.checksum_finalize();
}

void PacketHeaderTCP::update_checksum(const IPv4Address &srcip, const IPv4Address &destip) {
    checksum = 0;
    checksum = calculate_checksum(srcip, destip);
}

void PacketHeaderTCP::check(const IPv4Address &srcip, const IPv4Address &destip) const {
    if (calculate_checksum(srcip, destip) != 0) throw invalid_packet("Checksum");
    if (data_offset() < TCP_MIN_HEADER_LENGTH_QWORDS || data_offset() > TCP_MAX_HEADER_LENGTH_QWORDS) throw std::out_of_range("TCP data offset invalid");
    if (reserved() != 0) throw invalid_packet("TCP reserved bits invalid");
    if (syn() && (fin() || rst())) throw invalid_packet("SYN and FIN or RST bits set");
}

void PacketHeaderTCP::build(uint16_t sport, uint16_t dport, uint32_t seq) {
    source_port = sport;
    dest_port = dport;
    flags = 0;
    window_size = TCP_DEFAULT_WINDOW_SIZE;
    reserved(0);
    ns(false);
    urg_ptr = 0;
    seq_num = seq;
    ack_num = 0;
    data_offset_bytes(minimum_header_size());
}

void PacketHeaderTCP::print(std::ostream &os) const {
    os << "TCP packet:\n";
    os << " Source Port: " << source_port() << "\n";
    os << " Dest Port: " << dest_port() << "\n";
    os << " Sequence Number: " << seq_num() << "\n";
    os << " Ack Number: " << ack_num() << "\n";
    os << " Data Offset: " << data_offset() << " (" << data_offset_bytes() << " bytes)\n";
    os << " Reserved: " << reserved() << "\n";
    os << " Flags: " << flags() << "\n";
    os << "  NS: " << ns() << "\n";
    os << "  CWR: " << cwr() << "\n";
    os << "  ECE: " << ece() << "\n";
    os << "  URG: " << urg() << "\n";
    os << "  ACK: " << ack() << "\n";
    os << "  PSH: " << psh() << "\n";
    os << "  RST: " << rst() << "\n";
    os << "  SYN: " << syn() << "\n";
    os << "  FIN: " << fin() << "\n";
    os << " Window Size: " << window_size() << "\n";
    os << " Checksum: " << checksum() << "\n";
    os << " Urgent Pointer: " << urg_ptr() << "\n";
    //os << " Options: " << options << "\n";
}
