#ifndef NetDriver_h
#define NetDriver_h

#include <string>
#include "PacketBuffer.hpp"

class NetDriver {
protected:
    std::string ifname;
public:
    NetDriver(const std::string_view ifn) : ifname(ifn) {}
    virtual ~NetDriver() {}
    virtual void send(PacketBuffer &) = 0;
    virtual bool recv(PacketBuffer &) = 0;
    virtual size_t header_size() = 0;
    
    const std::string &get_ifname() { return ifname; }
};

#endif /* NetDriver_h */
