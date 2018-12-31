#include "OSNetwork.hpp"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <ifaddrs.h>

#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>
#include <sys/ioctl.h>

#ifndef __linux__
#include <net/if_dl.h>
#endif

#if defined(__APPLE__) && !defined(SA_SIZE)
#define SA_SIZE(sa)                                            \
(  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?  \
sizeof(long)         :                               \
((struct sockaddr *)(sa))->sa_len )
#endif

#ifndef SA_SIZE
#error "SA_SIZE not defined"
#endif

IPv4Address OSNetwork::get_local_addr_for_remote(const IPv4Address &dest) {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) throw std::system_error(errno, std::generic_category(), "socket");

    sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));

    sa.sin_addr.s_addr = dest.ip_int;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53); // Not actually used.
    sa.sin_len = sizeof(sa);

    int r = connect(sock, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa));
    if (r < 0) {
        close(sock);
        throw std::system_error(errno, std::generic_category(), "connect");
    }

    socklen_t len = sizeof(sa);
    r = getsockname(sock, reinterpret_cast<struct sockaddr *>(&sa), &len);
    if (r < 0) {
        close(sock);
        throw std::system_error(errno, std::generic_category(), "getsockname");
    }

    close(sock);

    return sa.sin_addr.s_addr;
}

#if defined(__APPLE__) || defined(BSD)
OSRouteInfo4 OSNetwork::get_next_hop(const IPv4Address &dest) {
    OSRouteInfo4 ri;
    ssize_t r;
    pid_t my_pid = getpid();
    const int MY_SEQ = 1;

    int sock4 = socket(PF_ROUTE, SOCK_RAW, AF_INET);
    if (sock4 < 0) std::system_error(errno, std::generic_category(), "socket");

    // freebsd route.c does it this way
    struct {
        struct  rt_msghdr m_rtm;
        union {
            char    m_space[512];
            struct  sockaddr_in sa_in;
        } next;
    } m_rtmsg;

    memset(&m_rtmsg, 0, sizeof(m_rtmsg));

    m_rtmsg.next.sa_in.sin_family = AF_INET;
    m_rtmsg.next.sa_in.sin_addr.s_addr = dest.ip_int;
    m_rtmsg.next.sa_in.sin_len = sizeof(struct sockaddr_in);

    m_rtmsg.m_rtm.rtm_type = RTM_GET;
    m_rtmsg.m_rtm.rtm_version = RTM_VERSION;
    m_rtmsg.m_rtm.rtm_addrs = RTA_DST;
    m_rtmsg.m_rtm.rtm_pid = my_pid;
    m_rtmsg.m_rtm.rtm_seq = MY_SEQ;
    m_rtmsg.m_rtm.rtm_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in);

    r = write(sock4, &m_rtmsg, m_rtmsg.m_rtm.rtm_msglen);
    if (r < 0) throw std::system_error(errno, std::generic_category(), "PF_ROUTE send");

    do {
        r = read(sock4, &m_rtmsg, sizeof(m_rtmsg));
        if (r < 0 || r < sizeof(struct rt_msghdr)) throw std::system_error(errno, std::generic_category(), "PF_ROUTE recv");
    } while (m_rtmsg.m_rtm.rtm_pid != my_pid && m_rtmsg.m_rtm.rtm_seq != MY_SEQ);
    close(sock4);

    ri.mtu = m_rtmsg.m_rtm.rtm_rmx.rmx_mtu;

    char *sa_ptr = m_rtmsg.next.m_space;
    struct sockaddr_in temp_in;
    //struct sockaddr_dl temp_dl;
    struct sockaddr    temp_sa;

    for(size_t i = 0; i < RTAX_MAX; i++) {
        switch(i) {
            case RTAX_DST:
                memcpy(&temp_in, sa_ptr, sizeof(sockaddr_in));
                ri.dest_net = temp_in.sin_addr.s_addr;
                break;

            case RTAX_GATEWAY:
                memcpy(&temp_in, sa_ptr, sizeof(sockaddr_in));
                ri.next_hop = temp_in.sin_addr.s_addr;
                break;

            case RTAX_NETMASK:
                memcpy(&temp_in, sa_ptr, sizeof(sockaddr_in));
                ri.dest_mask = temp_in.sin_addr.s_addr;
                break;

            /* These seem to not be present on OSX. Do we need them?
            case RTAX_IFA:
                memcpy(&temp_in, sa_ptr, sizeof(sockaddr_in));
                ri.local_addr = temp_in.sin_addr.s_addr;
                break;

            case RTAX_IFP:
                memcpy(&temp_dl, sa_ptr, sizeof(sockaddr_dl));
                if (temp_dl.sdl_nlen) ri.iface = std::string(temp_dl.sdl_data, temp_dl.sdl_nlen);
                break;*/

            default: // Not parsing this message
                break;
        }
        memcpy(&temp_sa, sa_ptr, sizeof(sockaddr));
        sa_ptr += SA_SIZE(&temp_sa);
        if (sa_ptr >= m_rtmsg.next.m_space + r) throw std::out_of_range("OOB processing route");
    }

    return ri;
}
#endif

OSInterfaces OSNetwork::get_interfaces() {
    OSInterfaces ifs = std::make_unique<OSInterfacesMap>();
    struct ifaddrs *ifap;
    struct sockaddr_dl sdp;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) throw std::system_error(errno, std::generic_category(), "socket");

    if (getifaddrs(&ifap) != 0) throw std::runtime_error("getifaddrs");

    struct ifreq ifr;
    struct sockaddr_in sa_in;
    //struct sockaddr_in6 sa_in6;

    struct ifaddrs *p;
    for (p = ifap; p; p = p->ifa_next) {
        if (p->ifa_addr && p->ifa_addr->sa_family == AF_LINK) {
            OSInterfaceInfo ifi;
            if (p->ifa_addr->sa_len < sizeof(struct sockaddr_dl)) throw std::runtime_error("sa_len value unexpected!");
            memcpy(&sdp, p->ifa_addr, sizeof(struct sockaddr_dl)); // Avoid aliasing
            memcpy(ifi.ethernet_address.data(), sdp.sdl_data + sdp.sdl_nlen, ifi.ethernet_address.size());
            ifi.name = p->ifa_name;

            memset(&ifr, 0, sizeof(ifr));
            ifr.ifr_addr.sa_family = AF_INET;
            if (IFNAMSIZ - 1 < strlen(p->ifa_name)) throw std::out_of_range("strlen");
            strncpy(ifr.ifr_name, p->ifa_name, strlen(p->ifa_name));

            if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) ifi.up = ifr.ifr_ifru.ifru_flags & IFF_RUNNING;

            if (ioctl(sock, SIOCGIFADDR, &ifr) >= 0) {
                memcpy(&sa_in, &ifr.ifr_ifru.ifru_addr, sizeof(sa_in));
                ifi.ipv4_address.addr = sa_in.sin_addr.s_addr;
            }

            if (ioctl(sock, SIOCGIFNETMASK, &ifr) >= 0) {
                memcpy(&sa_in, &ifr.ifr_ifru.ifru_addr, sizeof(sa_in));
                ifi.ipv4_address.mask = IPv4SubnetMask(IPv4Address(sa_in.sin_addr.s_addr).as_string()).mask;
            }

            if (ioctl(sock, SIOCGIFMTU, &ifr) >= 0) ifi.mtu = ifr.ifr_ifru.ifru_mtu;

            try {
                ifs->emplace(ifi.name, ifi);
            } catch (...) {
                freeifaddrs(ifap);
                close(sock);
                throw;
            }
        }
    }

    freeifaddrs(ifap);
    close(sock);
    return ifs;
}
