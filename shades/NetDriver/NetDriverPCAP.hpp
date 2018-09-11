#ifndef NetDriverPCAP_h
#define NetDriverPCAP_h

#include <pcap.h>

#include "NetDriver.hpp"
#include "PacketBuffer.hpp"

class NetDriverPCAP: public NetDriver {
private:
    pcap_t *pcap = nullptr;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int datalink_header = PacketBuffer::HEADER_UNKNOWN;
    size_t pcap_header_size = 0;
    
    PacketBuffer::HEADER_TYPE guess_loop_header_type(const u_char *);
    PacketBuffer::HEADER_TYPE guess_raw_header_type(const u_char *);
public:
    NetDriverPCAP(const std::string_view);
    ~NetDriverPCAP();
    void send(PacketBuffer &, size_t = 0);
    bool recv(PacketBuffer &, int);
    inline size_t header_size() { return pcap_header_size; }
    bool is_layer3_interface();
};

#endif /* NetDriverPCAP_h */
