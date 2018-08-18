#include "PacketHeaderTCP.hpp"

uint16_t PacketHeaderTCP::calculate_checksum() const {
    InetChecksumCalculator icc;
    icc.checksum_update(pbo.data(), pbo.size());
    return icc.checksum_finalize();
}

void PacketHeaderTCP::update_checksum() {
    checksum = 0;
    checksum = calculate_checksum();
}

void PacketHeaderTCP::check() const {
    if (calculate_checksum() != 0) throw invalid_packet("Checksum");
    if (data_offset() < TCP_MIN_HEADER_LENGTH_QWORDS || data_offset() > TCP_MAX_HEADER_LENGTH_QWORDS) throw std::out_of_range("TCP data offset invalid");
    if (reserved() != 0) throw invalid_packet("TCP reserved bits invalid");
    if (syn() && (fin() || rst())) throw invalid_packet("SYN and FIN or RST bits set");
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
