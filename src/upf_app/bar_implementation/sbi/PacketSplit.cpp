#include "PacketSplit.hpp"
#include <arpa/inet.h> //Inclusion of definitions for IP address conversion and network address manipulation functions
#include <iostream>//Including definitions to manipulate the input/output display format
#include "../helpers/Sqlite3Helper.hpp"

// Extract Ethernet header information
std::vector<std::string> SplitPacket::extractEthernetData(const struct ethhdr* ethernetHeader) {
    std::vector<std::string> ethernetData; //A vector of character strings to store Ethernet header information.
    ethernetData.push_back(std::string(ether_ntoa((struct ether_addr*)&ethernetHeader->h_source)));//Add source addresse to the Data ethernet vector. 
    ethernetData.push_back(std::string(ether_ntoa((struct ether_addr*)&ethernetHeader->h_dest)));//Add destination addresse to the Data ethernet vector. 
    ethernetData.push_back(std::to_string(ntohs(ethernetHeader->h_proto)));//Add protocol type to vector ethernet Data
    // // Displaying fields
    std::cout << "Ethernet Data:" << std::endl;
    for (const std::string& data : ethernetData) {
        std::cout << data << std::endl;
    }
    return ethernetData;

}

// Extract IPv4 header information
std::vector<std::string> SplitPacket::extractIPv4Data(const struct iphdr* ipHeader) {
    std::vector<std::string> ipv4Data;//A vector of character strings to store IPv4 header information.
    ipv4Data.push_back("Version: " + std::to_string((unsigned int)ipHeader->version));
    ipv4Data.push_back("Header Length: " + std::to_string((unsigned int)(ipHeader->ihl * 4)) + " bytes");
    ipv4Data.push_back("Type of Service: " + std::to_string((unsigned int)ipHeader->tos));
    ipv4Data.push_back("Total Length: " + std::to_string(ntohs(ipHeader->tot_len)) + " bytes");
    ipv4Data.push_back("Identification: " + std::to_string(ntohs(ipHeader->id)));
    ipv4Data.push_back("Flags: " + std::to_string((unsigned int)((ntohs(ipHeader->frag_off) & 0xE000) >> 13)));
    ipv4Data.push_back("Fragment Offset: " + std::to_string(ntohs(ipHeader->frag_off) & 0x1FFF));
    ipv4Data.push_back("Time to Live: " + std::to_string((unsigned int)ipHeader->ttl));
    ipv4Data.push_back("Protocol: " + std::to_string((unsigned int)ipHeader->protocol));
    ipv4Data.push_back("Header Checksum: " + std::to_string(ntohs(ipHeader->check)));
    ipv4Data.push_back("Source IP: " + std::string(inet_ntoa(*(struct in_addr*)&(ipHeader->saddr))));
    ipv4Data.push_back("Destination IP: " + std::string(inet_ntoa(*(struct in_addr*)&(ipHeader->daddr))));
    // // Displaying fields
    std::cout << "IPv4 Data:" << std::endl;
    for (const std::string& data : ipv4Data) {
        std::cout << data << std::endl;
    }
    return ipv4Data;
}

// Extract TCP header information
std::vector<std::string> SplitPacket::extractTCPData(const struct tcphdr* tcpHeader) {
    std::vector<std::string> tcpData;//A vector of character strings to store TCP header information.
    tcpData.push_back("Source Port: " + std::to_string(ntohs(tcpHeader->source)));
    tcpData.push_back("Destination Port: " + std::to_string(ntohs(tcpHeader->dest)));
    tcpData.push_back("Sequence Number: " + std::to_string(ntohl(tcpHeader->seq)));
    tcpData.push_back("Acknowledgment Number: " + std::to_string(ntohl(tcpHeader->ack_seq)));
    tcpData.push_back("Header Length: " + std::to_string((unsigned int)tcpHeader->doff * 4) + " bytes");
    //tcpData.push_back("Reserved: " + std::to_string((unsigned int)((ntohs(tcpHeader->res1) << 3) | (tcpHeader->res2 >> 5))));
    tcpData.push_back("Flags: " + std::to_string((unsigned int)tcpHeader->urg) + std::to_string((unsigned int)tcpHeader->ack) + std::to_string((unsigned int)tcpHeader->psh) + std::to_string((unsigned int)tcpHeader->rst) + std::to_string((unsigned int)tcpHeader->syn) + std::to_string((unsigned int)tcpHeader->fin));
    tcpData.push_back("Window Size: " + std::to_string(ntohs(tcpHeader->window)));
    tcpData.push_back("Checksum: " + std::to_string(ntohs(tcpHeader->check)));
    tcpData.push_back("Urgent Pointer: " + std::to_string(ntohs(tcpHeader->urg_ptr)));
    // Extracting TCP options if present
    if (tcpHeader->doff > 5) {//If doff is greater than 5, it means that the TCP header is longer than the standard 20 bytes, indicating the presence of TCP options.
        unsigned int optionsSize = (tcpHeader->doff - 5) * 4;
        tcpData.push_back("TCP Options Size: " + std::to_string(optionsSize) + " bytes");
     }
    // // Displaying fields
    std::cout << "TCP Data:" << std::endl;
    for (const std::string& data : tcpData) {
        std::cout << data << std::endl;
    }
    return tcpData;
}

// Extract UDP header information
std::vector<std::string> SplitPacket::extractUDPData(const struct udphdr* udpHeader, int packetLength) {
    std::vector<std::string> udpData;
    udpData.push_back("Source Port: " + std::to_string(ntohs(udpHeader->source)));
    udpData.push_back("Destination Port: " + std::to_string(ntohs(udpHeader->dest)));
    udpData.push_back("Length: " + std::to_string(ntohs(udpHeader->len)) + " bytes");
    udpData.push_back("Checksum: " + std::to_string(ntohs(udpHeader->check)));
    int udpPayloadLength = packetLength - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);
    udpData.push_back("UDP Payload Length: " + std::to_string(udpPayloadLength) + " bytes");
    // // Displaying fields
    std::cout << "UDP Data:" << std::endl;
    for (const std::string& data : udpData) {
        std::cout << data << std::endl;
    }
    return udpData;
}
// Extract ICMP header information
std::vector<std::string> SplitPacket::extractICMPData(const struct icmphdr* icmpHeader) {
    std::vector<std::string> icmpData;
    icmpData.push_back("Type: " + std::to_string((unsigned int)icmpHeader->type));
    icmpData.push_back("Code: " + std::to_string((unsigned int)icmpHeader->code));
    icmpData.push_back("Checksum: " + std::to_string(ntohs(icmpHeader->checksum)));
    // // Displaying fields
    std::cout << "ICMP Data:" << std::endl;
    for (const std::string& data : icmpData) {
        std::cout << data << std::endl;
    }
    return icmpData;
}

// Extract ICMPv6 header information
//std::vector<std::string> SplitPacket::extractICMPv6Data(const struct icmp6_hdr* icmpv6Header) {
    //std::vector<std::string> icmpv6Data;
    //icmpv6Data.push_back("Type: " + std::to_string((unsigned int)icmpv6Header->icmp6_type));
    //icmpv6Data.push_back("Code: " + std::to_string((unsigned int)icmpv6Header->icmp6_code));
    //icmpv6Data.push_back("Checksum: " + std::to_string(ntohs(icmpv6Header->icmp6_cksum)));
    //icmpv6Data.push_back("Max Response Delay: " + std::to_string(ntohl(icmpv6Header->icmp6_maxdelay)));
    //icmpv6Data.push_back("Reserved: " + std::to_string(ntohl(icmpv6Header->icmp6_dataun.icmp6_un_data32[0])));
    //icmpv6Data.push_back("Multicast Address: " + std::string(inet_ntoa(icmpv6Header->icmp6_dataun.icmp6_un_data32[1])));
    //return icmpv6Data;
//}

// Extract IGMP header information
//std::vector<std::string> SplitPacket::extractIGMPData(const struct igmp* igmpHeader) {
    //std::vector<std::string> igmpData;
    //igmpData.push_back("IGMP Version: " + std::to_string((unsigned int)igmpHeader->igmp_version));
    //igmpData.push_back("Type: " + std::to_string((unsigned int)igmpHeader->igmp_type));
    //igmpData.push_back("Max Resp Time: " + std::to_string((unsigned int)igmpHeader->igmp_maxresp));
    //igmpData.push_back("Checksum: " + std::to_string(ntohs(igmpHeader->igmp_cksum)));
    //igmpData.push_back("Multicast Address: " + std::string(inet_ntoa(igmpHeader->igmp_group)));
    //igmpData.push_back("S Flag: " + std::to_string((unsigned int)((igmpHeader->igmp_code >> 3) & 0x1)));
    //igmpData.push_back("QRV: " + std::to_string((unsigned int)((igmpHeader->igmp_code >> 1) & 0x3)));
    //igmpData.push_back("QQIC: " + std::to_string((unsigned int)igmpHeader->igmp_qqi));
    //igmpData.push_back("Number of Sources (NumSrc): " + std::to_string(ntohs(igmpHeader->igmp_numsrc)));
    //return igmpData;
//}

// Extract DNS header information
//std::vector<std::string> SplitPacket::extractDNSData(const struct dnshdr* dnsHeader) {
    //std::vector<std::string> dnsData;
    //dnsData.push_back("ID: " + std::to_string(ntohs(dnsHeader->id)));
    //dnsData.push_back("Flags: " + std::to_string(ntohs(dnsHeader->flags)));
    //dnsData.push_back("Questions: " + std::to_string(ntohs(dnsHeader->qdcount)));
    //dnsData.push_back("Answer RRs: " + std::to_string(ntohs(dnsHeader->ancount)));
    //dnsData.push_back("Authority RRs: " + std::to_string(ntohs(dnsHeader->nscount)));
    //dnsData.push_back("Additional RRs: " + std::to_string(ntohs(dnsHeader->arcount)));

    // Placeholder for actual DNS query and response parsing
    //dnsData.push_back("Queries: " + std::to_string(ntohs(dnsHeader->qdcount))); // Nombre de requêtes
    //dnsData.push_back("Answers: " + std::to_string(ntohs(dnsHeader->ancount))); // Nombre de réponses
    //dnsData.push_back("Authorities: " + std::to_string(ntohs(dnsHeader->nscount))); // Nombre d'autorités
    //dnsData.push_back("Additionals: " + std::to_string(ntohs(dnsHeader->arcount))); // Nombre d'informations supplémentaires

    //return dnsData;
//}


// Extract NBNS header information
//std::vector<std::string> SplitPacket::extractNBNSData(const struct nbns* nbnsHeader) {
   //std::vector<std::string> nbnsData;
    //nbnsData.push_back("Transaction ID: " + std::to_string(ntohs(nbnsHeader->trans_id)));
    //nbnsData.push_back("Flags: " + std::to_string(ntohs(nbnsHeader->flags)));
    //nbnsData.push_back("Opcode: " + std::to_string((unsigned int)((ntohs(nbnsHeader->flags) >> 11) & 0xF)));
    //nbnsData.push_back("Recursion Desired: " + std::to_string((unsigned int)((ntohs(nbnsHeader->flags) >> 8) & 0x1)));
    //nbnsData.push_back("Broadcast: " + std::to_string((unsigned int)(ntohs(nbnsHeader->flags) & 0x8000)));
    //nbnsData.push_back("Questions: " + std::to_string(ntohs(nbnsHeader->qdcount)));
    //nbnsData.push_back("Answer RRs: " + std::to_string(ntohs(nbnsHeader->ancount)));
    //nbnsData.push_back("Authorities: " + std::to_string(ntohs(nbnsHeader->nscount)));
    //nbnsData.push_back("Additionals: " + std::to_string(ntohs(nbnsHeader->arcount)));
    // Placeholder for actual NBNS query and response parsing
    //return nbnsData;
//}

// Extract SMB header information
//std::vector<std::string> SplitPacket::extractSMBData(const struct smb* smbHeader) {
    //std::vector<std::string> smbData;
    //smbData.push_back("Command: " + std::to_string(smbHeader->command));
    //smbData.push_back("Election Version: " + std::to_string(smbHeader->election_version));
    //smbData.push_back("Election Criteria: " + std::to_string(smbHeader->election_criteria));
    //smbData.push_back("Uptime: " + std::to_string(ntohl(smbHeader->uptime)));
    // Assuming server_name is a string
    //smbData.push_back("Server Name: " + std::string(smbHeader->server_name));

    // Placeholder for actual SMB data parsing

    //return smbData;
//}

// Extract QUIC header information
//std::vector<std::string> SplitPacket::extractQUICData(const struct quic* quicHeader) {
    //std::vector<std::string> quicData;
    //quicData.push_back("Header Form: " + std::to_string((unsigned int)((quicHeader->flags >> 7) & 0x1)));
    //quicData.push_back("Fixed Bit: " + std::to_string((unsigned int)((quicHeader->flags >> 6) & 0x1)));
    //quicData.push_back("Packet Type: " + std::to_string((unsigned int)(quicHeader->flags & 0x3F)));
    //quicData.push_back("Version: " + std::to_string(ntohs(quicHeader->version)));
    //quicData.push_back("Destination Connection ID Length: " + std::to_string((unsigned int)((quicHeader->flags >> 4) & 0x3)));
    //quicData.push_back("Destination Connection ID: " + std::to_string(ntohs(quicHeader->destination_connection_id)));
    //quicData.push_back("Source Connection ID Length: " + std::to_string((unsigned int)((quicHeader->flags >> 2) & 0x3)));
    //quicData.push_back("Source Connection ID: " + std::to_string(ntohs(quicHeader->source_connection_id)));
    //quicData.push_back("Length: " + std::to_string(ntohs(quicHeader->length)));
    //quicData.push_back("Remaining Payload: " + std::to_string(ntohs(quicHeader->remaining_payload)));
    // Placeholder for actual QUIC data parsing
    //return quicData;
//}

// Extract GTP-U header information
//std::vector<std::string> SplitPacket::extractGTPUData(const struct gtpu* gtpuHeader, const u_char* packetData) {
    //std::vector<std::string> gtpuData;
    //unsigned int offset = sizeof(struct udphdr);
    //unsigned int flagsAndType = ntohs(*(uint16_t*)&packetData[offset]);
    //gtpuData.push_back("Flags: " + std::to_string(flagsAndType >> 13));
    //gtpuData.push_back("Message Type: " + std::to_string(flagsAndType & 0x00FF));
    //gtpuData.push_back("Length: " + std::to_string(ntohs(*(uint16_t*)&packetData[offset + 2])));
    //gtpuData.push_back("TEID: " + std::to_string(ntohl(*(uint32_t*)&packetData[offset + 4])));
    //return gtpuData;
///}

void SplitPacket::processPacket(const u_char* packetData, int packetLength) {
    struct ethhdr* ethernetHeader = (struct ethhdr*)packetData;//Interprets the start of the packet data as an Ethernet header.
    std::vector<std::string> ethernetData = extractEthernetData(ethernetHeader); //Function to extract data from the Ethernet header, returns a vector of character strings.

    if (ntohs(ethernetHeader->h_proto) == ETH_P_IP) {//Converts the h_proto field of the Ethernet header to host byte order to check if it is an IPv4 protocol (ETH_P_IP).
        struct iphdr* ipHeader = (struct iphdr*)(packetData + sizeof(struct ethhdr));//Interprets the data after the Ethernet header as an IPv4 header.
        std::vector<std::string> ipv4Data = extractIPv4Data(ipHeader);//Function to extract data from IPv4 header,

        if (ipHeader->protocol == IPPROTO_TCP) {//Checks if the protocol is TCP.
            struct tcphdr* tcpHeader = (struct tcphdr*)(packetData + sizeof(struct ethhdr) + ipHeader->ihl * 4);//Interprets the data after the Ethernet header and the IPv4 header as a TCP header.
            std::vector<std::string> tcpData = extractTCPData(tcpHeader);//Function to extract data from TCP header,
        } else if (ipHeader->protocol == IPPROTO_UDP) {//Checks if the protocol is UDP.
            struct udphdr* udpHeader = (struct udphdr*)(packetData + sizeof(struct ethhdr) + ipHeader->ihl * 4);//Interprets the data after the Ethernet header and the IPv4 header as a UDP header.
            std::vector<std::string> udpData = extractUDPData(udpHeader, packetLength);//Function to extract data from UDP header,

            // Add GTP-U handling if necessary
        } //else if (ipHeader->protocol == IPPROTO_ICMP) {
            //struct icmphdr* icmpHeader = (struct icmphdr*)(packetData + sizeof(struct ethhdr) + ipHeader->ihl * 4);
            //std::vector<std::string> icmpData = extractICMPData(icmpHeader);
        //} else if (ipHeader->protocol == IPPROTO_IGMP) {
            //struct igmp* igmpHeader = (struct igmp*)(packetData + sizeof(struct ethhdr) + ipHeader->ihl * 4);
            //std::vector<std::string> igmpData = extractIGMPData(igmpHeader);
        //} else if (ipHeader->protocol == IPPROTO_ICMPV6) {
            //struct icmp6_hdr* icmpv6Header = (struct icmp6_hdr*)(packetData + sizeof(struct ethhdr) + ipHeader->ihl * 4);
            //std::vector<std::string> icmpv6Data = extractICMPv6Data(icmpv6Header);
        //}
    }
}


