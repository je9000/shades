#!/bin/sh

clang++ -INetDriver -INetworking -IPacketHeaders -I. -lpcap -std=c++14 -stdlib=libc++ main.cpp
