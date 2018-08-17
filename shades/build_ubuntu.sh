#!/bin/sh

# apt install clang-6.0 libc++1 libpcap-dev libc++-dev clang-6.0-dev libc++abi-dev lldb-6.0

/usr/lib/llvm-6.0/bin/clang++ -I/usr/include/c++/v1/ -INetDriver -INetworking -IPacketHeaders -IUtil -lpcap -std=c++17 -stdlib=libc++ -g -oshades main.cpp
