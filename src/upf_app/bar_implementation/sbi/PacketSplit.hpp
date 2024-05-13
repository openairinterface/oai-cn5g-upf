#ifndef PACKET_SPLIT_HPP
#define PACKET_SPLIT_HPP

#include <iostream>
#include <netinet/ip.h>      // For IPv4 header structure
#include <netinet/tcp.h>     // For TCP header structure
#include <netinet/udp.h>     // For UDP header structure
#include <netinet/ip_icmp.h> // For ICMP header structure
#include <netinet/ether.h>   // For Ethernet header structure
#include <netinet/in.h>      // For struct in_addr
#include <string>            // For std::string

class SplitPacket {
public:
    static void processPacket(const u_char* packetData, int packetLength);
};

#endif // PACKET_SPLIT_HPP
