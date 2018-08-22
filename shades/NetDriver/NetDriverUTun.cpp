#include <exception>

#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <net/if.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>

#include "PacketHeaderIPv4.hpp"
#include "NetDriverUTun.hpp"

NetDriverUTun::NetDriverUTun(const std::string_view id) : NetDriver(id) {
    if (std::sscanf(id.data(), "%d", &utun_id) != 1) throw std::runtime_error("Invalid utun number");
    utun_fd = create_utun(utun_id);
}

NetDriverUTun::~NetDriverUTun() {
    close(utun_fd);
}

int NetDriverUTun::create_utun(int devno) {
    struct ctl_info ctl;
    __attribute__((__may_alias__)) struct sockaddr_ctl sa_sc;
    int r;
    char new_if_name[IFNAMSIZ + 1];
    socklen_t new_if_name_len = IFNAMSIZ;

    memset(&ctl, 0, sizeof(ctl));
    memset(&sa_sc, 0, sizeof(sa_sc));

    if (snprintf(ctl.ctl_name, sizeof(ctl.ctl_name), "%s", UTUN_CONTROL_NAME) != strlen(UTUN_CONTROL_NAME)) {
        throw std::overflow_error("snprintf() ctl_info");
    }

    r = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (r < 0) std::system_error(errno, std::generic_category(), "socket");

    if (ioctl(r, CTLIOCGINFO, &ctl) == -1) {
        close(r);
        throw std::system_error(errno, std::generic_category(), "ioctl");
    }

    sa_sc.sc_id = ctl.ctl_id;
    sa_sc.sc_len = sizeof(sa_sc);
    sa_sc.sc_family = AF_SYSTEM;
    sa_sc.ss_sysaddr = AF_SYS_CONTROL;
    sa_sc.sc_unit = devno;

    if (connect(r, reinterpret_cast<struct sockaddr *>(&sa_sc), sizeof(sa_sc)) < 0) {
        close(r);
        throw std::system_error(errno, std::generic_category(), "connect");
    }

    if (getsockopt(r, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, static_cast<char *>(new_if_name), &new_if_name_len) < 0) {
        close(r);
        throw std::system_error(errno, std::generic_category(), "getsockopt");
    }
    
    ifname = std::string(new_if_name, new_if_name_len);

    return r;
}

void NetDriverUTun::send(PacketBuffer &pb) {
    // The first 4 bits of a layer 3 header are the IP version. And utun only supports IP!
    uint32_t ip_version = pb.data()[0] >> 4;
    
    switch (ip_version) {
        case 4:
            ip_version = htonl(AF_INET);
            break;
        case 6:
            ip_version = htonl(AF_INET6);
            break;
        default:
            throw std::runtime_error("Unsupported packet type");
    }
    
    pb.unreserve_space(HEADER_SIZE);
    memcpy(pb.data(), &ip_version, HEADER_SIZE);
    ssize_t r = write(utun_fd, pb.data(), pb.size());
    if (r != pb.size()) throw std::runtime_error("Unable to send all data");
}

bool NetDriverUTun::recv(PacketBuffer &pb) {
    uint32_t ip_version;
    pb.reset_reserved_space();
    pb.unreserve_space(HEADER_SIZE);
RETRY:
    ssize_t r = read(utun_fd, pb.data(), pb.size());
    if (r < 0 && (errno == EINTR || errno == EAGAIN)) goto RETRY;
    if (r <= 0 || r <= HEADER_SIZE) throw std::runtime_error("Unable to read all data");
    memcpy(&ip_version, pb.data(), HEADER_SIZE);

    pb.rereserve_space(HEADER_SIZE);
    pb.set_valid_size(r - HEADER_SIZE);
    
    switch (ntohl(ip_version)) {
        case AF_INET:
            pb.header_type = PacketBuffer::HEADER_IPV4;
            break;
        case AF_INET6:
            pb.header_type = PacketBuffer::HEADER_IPV6;
            break;
        default:
            pb.header_type = PacketBuffer::HEADER_UNKNOWN;
    }
    return true;
}

