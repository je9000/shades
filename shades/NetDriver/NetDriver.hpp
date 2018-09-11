#ifndef NetDriver_h
#define NetDriver_h

#include <string>
#include <string_view>
#include "PacketBuffer.hpp"

#if !defined(NETDRIVER_KQUEUE) && !defined(NETDRIVER_POLL)
/*
 * There's no good reason not to use kqueue on other platforms that
 * support it, but the OSX kqueue/utun interaction seems buggy so
 * let's only support kqueue on OSX so the normal OSs all get the
 * same code.
 */
#ifdef __APPLE__
#define NETDRIVER_KQUEUE
#else
#define NETDRIVER_POLL
#endif
#endif

#ifdef NETDRIVER_KQUEUE
#include <sys/event.h>
#include <sys/types.h>
#include <sys/time.h>
#endif

#ifdef NETDRIVER_POLL
#include <poll.h>
#endif

class NetDriver {
protected:
    std::string ifname;
    
    uint32_t get_mtu();
    bool socket_ready(int);
    void setup_socket_ready(int);
    
#ifdef NETDRIVER_KQUEUE
    // For some reason only kqueue sees events on the utun socket on OSX.
    struct kevent kq_chlist[1];
    struct kevent kq_evlist[1];
    struct timespec kq_timeout;
    int kq;
#endif
    
#ifdef NETDRIVER_POLL
    struct pollfd poll_data[1];
#endif
    
public:
    uint32_t mtu;
    enum ADDRTYPE {
        ETHERNET,
        IPV4,
        IPV6
    };
    NetDriver(const std::string_view ifn) : ifname(ifn) {}
    NetDriver(const NetDriver &) = delete;
    virtual ~NetDriver() {}
    virtual void send(PacketBuffer &, size_t = 0) = 0;
    virtual bool recv(PacketBuffer &, int) = 0; // Return true if we received data, false if it's just a timeout.
    virtual bool is_layer3_interface() = 0;
    
    const std::string &get_ifname() { return ifname; }
};

#endif /* NetDriver_h */
