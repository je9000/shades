#include "NetDriver.hpp"

#include <stdexcept>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

uint32_t NetDriver::get_mtu() {
    struct ifreq ifr;

    if (mtu) return mtu;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (!sock) throw std::system_error(errno, std::generic_category(), "socket");
    
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname.data());
    
    if (ioctl(sock, SIOCGIFMTU, &ifr) < 0) {
        if (sock) close(sock);
        throw std::system_error(errno, std::generic_category(), "ioctl");
    }
    close(sock);
    mtu = ifr.ifr_mtu;
    return mtu;
}

void NetDriver::setup_socket_ready(int fd) {
    memset(&poll_data, 0, sizeof(poll_data));
    poll_data[0].fd = fd;
    poll_data[0].events = POLLIN;
}

bool NetDriver::socket_ready(int timeout_seconds) {
    int r;

RETRY_POLL:
    r = poll(poll_data, sizeof(poll_data) / sizeof(poll_data[0]), timeout_seconds * 1000);
    if (r < 0 && (errno == EINTR || errno == EAGAIN)) goto RETRY_POLL;
    if (r < 0) throw std::system_error(errno, std::generic_category(), "poll");
    if (r == 0) return false; // Timeout

    return true;
}
