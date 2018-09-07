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
