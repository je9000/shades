#include "PacketHeader.hpp"

std::ostream &operator<<(std::ostream &os, const PacketHeader &ph) {
    ph.print(os);
    return os;
}
