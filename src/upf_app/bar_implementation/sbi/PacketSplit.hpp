// Dans PacketSplit.hpp

#ifndef PACKET_SPLIT_HPP
#define PACKET_SPLIT_HPP

#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
//#include <netinet/dns.h>
//#include <netinet/mdns.h>
///#include <netinet/igmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
//#include <wireshark/...> 

#include <arpa/nameser.h>
#include <string>
#include <vector>

class SplitPacket {
public:
    // Methods to extract data from different headers
    static std::vector<std::string> extractEthernetData(const struct ethhdr* ethernetHeader);
    static std::vector<std::string> extractIPv4Data(const struct iphdr* ipHeader);
    static std::vector<std::string> extractTCPData(const struct tcphdr* tcpHeader);
    static std::vector<std::string> extractUDPData(const struct udphdr* udpHeader, int packetLength);
    static std::vector<std::string> extractICMPData(const struct icmphdr* icmpHeader);
    //static std::vector<std::string> extractICMPv6Data(const struct icmp6_hdr* icmpv6Header);
    //static std::vector<std::string> extractIGMPData(const struct igmp* igmpHeader); // Ajout pour IGMP
    //static std::vector<std::string> extractDNSData(const struct dnshdr* dnsHeader); // Ajout pour DNS
    //static std::vector<std::string> extractMDNSData(const struct mdns* mdnsHeader); // Ajout pour MDNS
    //static std::vector<std::string> extractNBNSData(const struct nbns* nbnsHeader);
    //static std::vector<std::string> extractSMBData(const struct smb* smbHeader);
    //static std::vector<std::string> extractQUICData(const struct quic* quicHeader);
    //static std::vector<std::string> extractGTPUData(const struct gtpu* gtpuHeader, const u_char* packetData);

    // packet processing method
    static void processPacket(const u_char* packetData, int packetLength);
};

#endif // PACKET_SPLIT_HPP
