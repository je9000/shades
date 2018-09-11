#include "NetDriver.hpp"

#include <stdexcept>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

uint32_t NetDriver::get_mtu() {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (!sock) throw std::system_error(errno, std::generic_category(), "socket");
    
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname.data());
    
    if (ioctl(sock, SIOCGIFMTU, &ifr) < 0) {
        if (sock) close(sock);
        throw std::system_error(errno, std::generic_category(), "ioctl");
    }
    close(sock);
    
    return ifr.ifr_mtu;
}

void NetDriver::setup_socket_ready(int fd) {
#ifdef NETDRIVER_KQUEUE
    kq = kqueue();
    if (!kq) throw std::system_error(errno, std::generic_category(), "kqueue");
    memset(&kq_chlist, 0, sizeof(kq_chlist));
    memset(&kq_evlist, 0, sizeof(kq_evlist));
    EV_SET(&kq_chlist[0], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
#endif
    
#ifdef NETDRIVER_POLL
    memset(&poll_data, 0, sizeof(poll_data));
    poll_data[0].fd = fd;
    poll_data[0].events = POLLIN;
#endif
}

bool NetDriver::socket_ready(int timeout_seconds) {
    int r;

#ifdef NETDRIVER_KQUEUE
RETRY_KQUEUE:
    kq_timeout.tv_sec = timeout_seconds;
    kq_timeout.tv_nsec = 0;
    r = kevent(kq, kq_chlist, sizeof(kq_chlist) / sizeof(kq_chlist[0]), kq_evlist, sizeof(kq_evlist) / sizeof(kq_evlist[0]), &kq_timeout);
    if (r < 0 && (errno == EINTR || errno == EAGAIN)) goto RETRY_KQUEUE;
    if (r < 0) throw std::system_error(errno, std::generic_category(), "kevent");
    if (r == 0) return false; // Timeout
#endif
    
#ifdef NETDRIVER_POLL
RETRY_POLL:
    r = poll(poll_data, sizeof(poll_data) / sizeof(poll_data[0]), timeout_seconds);
    if (r < 0 && (errno == EINTR || errno == EAGAIN)) goto RETRY_POLL;
    if (r < 0) throw std::system_error(errno, std::generic_category(), "poll");
    if (r == 0) return false; // Timeout
#endif

    return true;
}
