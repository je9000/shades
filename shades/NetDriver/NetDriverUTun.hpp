#ifndef NetDriverUTun_h
#define NetDriverUTun_h

#include <string_view>

#include "NetDriver.hpp"
#include "PacketBuffer.hpp"

class NetDriverUTun: public NetDriver {
private:
    const int HEADER_SIZE = 4;
    int utun_fd, utun_id;
public:
    NetDriverUTun(const std::string_view);
    
    ~NetDriverUTun();
    
    void send(PacketBuffer &, size_t = 0);
    bool recv(PacketBuffer &);
    
    int create_utun(int);
    
    inline bool is_layer3_interface() { return true; }
};

#endif /* NetDriverUTun_h */
