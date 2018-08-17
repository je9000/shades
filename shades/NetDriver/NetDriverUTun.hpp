#ifndef NetDriverUTun_h
#define NetDriverUTun_h

#include <exception>

#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <fcntl.h>
#include <unistd.h>

#include "NetDriver.hpp"
#include "PacketBuffer.hpp"

class NetDriverUTun: public NetDriver {
private:
    int utun_fd, utun_id;
public:
    NetDriverUTun(const std::string_view id) : NetDriver(id) {
        if (std::sscanf(id.data(), "%d", &utun_id) != 1) throw std::runtime_error("Invalid utun number");
        utun_fd = create_utun(utun_id);
    }
    
    ~NetDriverUTun() {
        close(utun_fd);
    }
    
    void send(const PacketBuffer &);
    bool recv(PacketBuffer &);
    size_t header_size() { return 0; }
    
    int create_utun(int);
};

int NetDriverUTun::create_utun(int devno) {
    struct ctl_info ctl;
    struct sockaddr_ctl sa_sc;
    int r;

    memset(&ctl, 0, sizeof(ctl));
    if (snprintf(ctl.ctl_name, sizeof(ctl.ctl_name), "%s", UTUN_CONTROL_NAME) != strlen(UTUN_CONTROL_NAME)) {
        throw std::overflow_error("snprintf() ctl_info");
    }
    
    r = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (r < 0) throw std::runtime_error("socket() failed");
    
    if (ioctl(r, CTLIOCGINFO, &ctl) == -1) {
        close(r);
        throw std::runtime_error("ioctl() failed");
    }

    memset(&sa_sc, 0, sizeof(sa_sc));
    sa_sc.sc_id = ctl.ctl_id;
    sa_sc.sc_len = sizeof(sa_sc);
    sa_sc.sc_family = AF_SYSTEM;
    sa_sc.ss_sysaddr = AF_SYS_CONTROL;
    sa_sc.sc_unit = devno;
    
    if (connect(r, reinterpret_cast<struct sockaddr *>(&sa_sc), sizeof(sa_sc)) < 0) {
        close(r);
        throw std::runtime_error("connect() failed");
    }
    
    return r;
}

#endif /* NetDriverUTun_h */
