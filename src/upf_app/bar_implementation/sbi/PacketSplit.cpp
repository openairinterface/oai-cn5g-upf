#include <arpa/inet.h>
#include <iomanip>
#include "PacketSplit.hpp"

void SplitPacket::processPacket(const u_char* packetData, int packetLength) {
    // Extract Ethernet header
    struct ethhdr* ethernetHeader = (struct ethhdr*)packetData;

    // Print Ethernet header information
    std::cout << "Ethernet Header:" << std::endl;
    std::cout << "   Source MAC: " << ether_ntoa((struct ether_addr*)&ethernetHeader->h_source) << std::endl;
    std::cout << "   Destination MAC: " << ether_ntoa((struct ether_addr*)&ethernetHeader->h_dest) << std::endl;
    std::cout << "   Ether Type: " << std::dec << ntohs(ethernetHeader->h_proto) << std::endl;

    // Extract IP header
    struct iphdr* ipHeader = (struct iphdr*)(packetData + sizeof(struct ethhdr));

    // Assuming Ethernet type is IP (0x0800)
    if (ntohs(ethernetHeader->h_proto) == 0x0800) {
        // Print IPv4 header information
        std::cout << "IPv4 Header:" << std::endl;
        std::cout << "   Version: " << (unsigned int)ipHeader->version << std::endl;
        std::cout << "   Header Length: " << (unsigned int)(ipHeader->ihl * 4) << " bytes" << std::endl;
        std::cout << "   Type of Service: " << (unsigned int)ipHeader->tos << std::endl;
        std::cout << "   Total Length: " << std::dec << ntohs(ipHeader->tot_len) << " bytes" << std::endl;
        std::cout << "   Identification: " << std::dec << ntohs(ipHeader->id) << std::endl;
        std::cout << "   Flags: " << (unsigned int)ipHeader->frag_off << std::endl;
        std::cout << "   Time to Live: " << (unsigned int)ipHeader->ttl << std::endl;
        std::cout << "   Protocol: " << (unsigned int)ipHeader->protocol << std::endl;
        std::cout << "   Header Checksum: " << std::dec << ntohs(ipHeader->check) << std::endl;
        std::cout << "   Source IP: " << inet_ntoa(*(struct in_addr*)&(ipHeader->saddr)) << std::endl;
        std::cout << "   Destination IP: " << inet_ntoa(*(struct in_addr*)&(ipHeader->daddr)) << std::endl;

        // Assuming IP protocol is TCP (6) or UDP (17) or ICMP (1) or GTP-U (132)
        if (ipHeader->protocol == 6) { // TCP
            // Extract TCP header
            struct tcphdr* tcpHeader = (struct tcphdr*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr));
            // Print TCP header information
            std::cout << "TCP Header:" << std::endl;
            std::cout << "   Source Port: " << std::dec << ntohs(tcpHeader->source) << std::endl;
            std::cout << "   Destination Port: " << std::dec << ntohs(tcpHeader->dest) << std::endl;
            std::cout << "   Sequence Number: " << std::dec << ntohl(tcpHeader->seq) << std::endl;
            std::cout << "   Acknowledgment Number: " << std::dec << ntohl(tcpHeader->ack_seq) << std::endl;
            std::cout << "   Header Length: " << (unsigned int)tcpHeader->doff * 4 << " bytes" << std::endl;
            std::cout << "   Flags: " << (unsigned int)tcpHeader->urg << (unsigned int)tcpHeader->ack << (unsigned int)tcpHeader->psh << (unsigned int)tcpHeader->rst << (unsigned int)tcpHeader->syn << (unsigned int)tcpHeader->fin << std::endl;
            std::cout << "   Window Size: " << std::dec << ntohs(tcpHeader->window) << std::endl;
            std::cout << "   Checksum: " << std::dec << ntohs(tcpHeader->check) << std::endl;
            std::cout << "   Urgent Pointer: " << std::dec << ntohs(tcpHeader->urg_ptr) << std::endl;
        } else if (ipHeader->protocol == 17) { // UDP
            // Extract UDP header
            struct udphdr* udpHeader = (struct udphdr*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr));
            // Print UDP header information
            std::cout << "UDP Header:" << std::endl;
            std::cout << "   Source Port: " << std::dec << ntohs(udpHeader->source) << std::endl;
            std::cout << "   Destination Port: " << std::dec << ntohs(udpHeader->dest) << std::endl;
            std::cout << "   Length: " << std::dec << ntohs(udpHeader->len) << " bytes" << std::endl;
            std::cout << "   Checksum: " << std::dec << ntohs(udpHeader->check) << std::endl;
        } else if (ipHeader->protocol == 1) { // ICMP
            // Extract ICMP header
            struct icmphdr* icmpHeader = (struct icmphdr*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr));
            // Print ICMP header information
            std::cout << "ICMP Header:" << std::endl;
            std::cout << "   Type: " << (unsigned int)icmpHeader->type << std::endl;
            std::cout << "   Code: " << (unsigned int)icmpHeader->code << std::endl;
            std::cout << "   Checksum: " << std::dec << ntohs(icmpHeader->checksum) << std::endl;
        } else if (ipHeader->protocol == 132) { // GTP-U
            // Extract GTP-U header
            struct udphdr* udpHeader = (struct udphdr*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr) + 20); // Skip the first 20 bytes
            // Print GTP-U header information
            std::cout << "GTP-U Header:" << std::endl;
            std::cout << "   Source IP: " << inet_ntoa(*(struct in_addr*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr) + 20)) << std::endl;
            std::cout << "   Destination IP: " << inet_ntoa(*(struct in_addr*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr) + 24)) << std::endl;
            std::cout << "   Source Port: " << std::dec << ntohs(*(uint16_t*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr) + 28)) << std::endl;
            std::cout << "   Destination Port: " << std::dec << ntohs(*(uint16_t*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr) + 30)) << std::endl;
            std::cout << "   Length: " << std::dec << ntohs(*(uint16_t*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr) + 32)) << std::endl;
            std::cout << "   SEID: " << std::dec << ntohl(*(uint32_t*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr) + 36)) << std::endl;
            std::cout << "   TEID: " << std::dec << ntohl(*(uint32_t*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr) + 40)) << std::endl;
            std::cout << "   Message Type: " << (unsigned int)(*(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr) + 42)) << std::endl;
            std::cout << "   Sequence Number: " << (unsigned int)(*(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr) + 43)) << std::endl;
            // Add more fields as needed
        }
    } else if (ntohs(ethernetHeader->h_proto) == 0x86DD) { // IPv6
        // Extract IPv6 header
        struct ip6_hdr* ipv6Header = (struct ip6_hdr*)(packetData + sizeof(struct ethhdr));
        // Print IPv6 header information
        std::cout << "IPv6 Header:" << std::endl;
        // Add fields from IPv6 header
    } else if (ntohs(ethernetHeader->h_proto) == 0x0806) { // ARP
        // Extract ARP header
        struct arphdr* arpHeader = (struct arphdr*)(packetData + sizeof(struct ethhdr));
        // Print ARP header information
        std::cout << "ARP Header:" << std::endl;
        // Add fields from ARP header
    } else if (ipHeader->protocol == 2) { // IGMP
        // Extract IGMP header
        struct igmp* igmpHeader = (struct igmp*)(packetData + sizeof(struct ethhdr) + sizeof(struct iphdr));
        // Print IGMP header information
        std::cout << "IGMP Header:" << std::endl;
        // Add fields from IGMP header
    } else if (ipHeader->protocol == 41) { // IPv6
        // Extract IPv6 header
        struct ip6_hdr* ipv6Header = (struct ip6_hdr*)(packetData + sizeof(struct ethhdr));
        // Print IPv6 header information
        std::cout << "IPv6 Header:" << std::endl;
        // Add fields from IPv6 header
    }

    // Extract data
    const u_char* data = packetData + sizeof(struct ethhdr) + sizeof(struct iphdr);
    int dataLength = packetLength - sizeof(struct ethhdr) - sizeof(struct iphdr);

    // Print data
    std::cout << "Data:" << std::endl;
    for (int i = 0; i < dataLength; ++i) {
        std::cout << std::dec << (int)data[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::endl;
}
