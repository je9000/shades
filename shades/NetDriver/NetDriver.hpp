#ifndef NetDriver_h
#define NetDriver_h

#include <string>
#include <string_view>
#include "PacketBuffer.hpp"

#include <poll.h>

class NetDriver {
protected:
    std::string ifname;
    uint32_t mtu = 0;

    bool socket_ready(int);
    void setup_socket_ready(int);
    struct pollfd poll_data[1];

public:
    enum ADDRTYPE {
        ETHERNET,
        IPV4,
        IPV6
    };

    size_t packet_count = 0;
    NetDriver(const std::string_view ifn) : ifname(ifn) {}
    NetDriver(const NetDriver &) = delete;
    virtual ~NetDriver() {}
    virtual void send(PacketBuffer &, size_t = 0) = 0;
    virtual bool recv(PacketBuffer &, int) = 0; // Return true if we received data, false if it's just a timeout.
    virtual bool is_layer3_interface() = 0;

    uint32_t get_mtu();
    const std::string &get_ifname() { return ifname; }
};

#endif /* NetDriver_h */
