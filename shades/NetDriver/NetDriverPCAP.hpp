#ifndef NetDriverPCAP_h
#define NetDriverPCAP_h

#include <pcap.h>

#include "NetDriver.hpp"
#include "PacketBuffer.hpp"

class NetDriverPCAP: public NetDriver {
private:
    pcap_t *pcap = nullptr;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int datalink_header = HEADER_UNKNOWN;
    size_t pcap_header_size = 0;
    
    PacketBufferHeaderType guess_loop_header_type(const u_char *);
    PacketBufferHeaderType guess_raw_header_type(const u_char *);
public:
    NetDriverPCAP(const std::string_view);
    ~NetDriverPCAP();
    void send(PacketBuffer &);
    bool recv(PacketBuffer &);
    size_t header_size() { return pcap_header_size; }
};

#endif /* NetDriverPCAP_h */
