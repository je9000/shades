# Shades

Packet parsing, crafting, networking library, and network stack for C++14.

# Description

Shades is a library designed to aid in parsing and crafting network packets.
Shades provides the basic building blocks for dealing with packets, but also
provides higher-level interfaces built on these blocks to implement an entire
networking stack, including TCP, UDP, IPv4 (IPv6 in progress), Ethernet, ARP,
etc.

Shades can be used to parse or craft individual packets, or act as a network
stack for custom applications. Components are layered together with callbacks
allowing easy modification of packets passing through the library. Callbacks
can be placed at different points in the network stack, for example: as packets
are received, after IP packets are reassembled, when TCP data arrives, etc.

Shades is designed to be relatively performant, but ease of use (for
developers) is a higher priority. There are no dependencies outside of the
standard library, and care is taken to avoid manual memory management. Manual
memory copying is done but in only a few places. The API is designed to be
simple.

Shades supports Linux and OSX, and hopefully FreeBSD, NetBSD, and OpenBSD.

# Examples

## shadescap

shadescap is sort of like tcpdump but built on shades. It uses shades for
packet capture, parsing, and printing. It shows packet headers in a more
readable (and verbose) format than tcpdump. It's not (yet?) a replacement for
tcpdump.

## sweep

sweep is a simple tool for pinging a bunch of IPs. It's not fast because of the
synchronous nature of shades, but it works and is a good example.

## other

shades/main.cpp has some examples of using shades, but is more for debugging
than as an example.

# License

Shades is licensed under the GPLv2.
