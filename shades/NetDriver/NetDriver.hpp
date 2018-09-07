#ifndef NetDriver_h
#define NetDriver_h

#include <string>
#include "PacketBuffer.hpp"

class NetDriver {
protected:
    std::string ifname;
public:
    enum ADDRTYPE {
        ETHERNET,
        IPV4,
        IPV6
    };
    NetDriver(const std::string_view ifn) : ifname(ifn) {}
    NetDriver(const NetDriver &) = delete;
    virtual ~NetDriver() {}
    virtual void send(PacketBuffer &, size_t = 0) = 0;
    virtual bool recv(PacketBuffer &) = 0; // Return true if we received data, false if it's just a timeout.
    virtual bool is_layer3_interface() = 0;
    
    const std::string &get_ifname() { return ifname; }
};

#endif /* NetDriver_h */
