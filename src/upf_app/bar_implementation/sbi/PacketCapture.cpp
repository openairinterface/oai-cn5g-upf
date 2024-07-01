#include <pcap.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <thread>

#include "PacketCapture.hpp"


PacketCapture::PacketCapture() {
    // Initialization if needed
}

/*------------------------------------------------------------------------------------*/
PacketCapture::~PacketCapture() {
    // Cleanup if needed
}

/*------------------------------------------------------------------------------------*/
pcap_t* PacketCapture::open_pcap(const char *interface){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    if (not (handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf))){
        std::cerr << "Error opening interface %s: " << interface << errbuf << std::endl;
    }
    return handle;
}

/*-------------------------------------------------------------------------------------*/
pcap_dumper_t* PacketCapture::getPcapDumper(){
    return pcapDumper;
}

/*------------------------------------------------------------------------------------*/
void PacketCapture::setPcapDumper(pcap_dumper_t* pcap){
    pcapDumper = pcap;
}


/*------------------------------------------------------------------------------------*/
int PacketCapture::captureTraffic(const char* interface, int packetCount, int delay, const char* filterExpr) {
     pcap_t* handle = open_pcap(interface);

    if (filterExpr && std::strlen(filterExpr) > 0) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filterExpr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Could not parse filter " << filterExpr << ": " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            return -1;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Could not install filter " << filterExpr << ": " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle);
            return -1;
        }
        pcap_freecode(&fp);
    }

    HandlerData handlerData;
    memset(&handlerData, 0, sizeof(handlerData));

    int ret = pcap_loop(handle, packetCount, handleTraffic, reinterpret_cast<u_char*>(&handlerData));
    if (ret == -1) {
        std::cerr << "Error in pcap_loop: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return -1;
    }

    if (delay > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    }

    pcap_close(handle);
    return 0;
}

/*------------------------------------------------------------------------------------*/
void PacketCapture::handleTraffic(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    HandlerData* handlerData = reinterpret_cast<HandlerData*>(userData);
    // Process the packet here
    std::cout << "Packet captured with length: " << pkthdr->len << std::endl;
}




// void PacketCapture::handleTraffic(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
//     PacketHandlerData* handlerData = reinterpret_cast<PacketHandlerData*>(userData);
//     int delay = handlerData->delay;
//     // Retrieve Sqlite3Helper object
//     Sqlite3Helper* sqlite3Helper = handlerData->sqlite3Helper;

//     // Create an instance of SplitPacket to process the packet.
//     SplitPacket splitPacket;

//     ////////////////////////////////////////////////////////////////////////////////////
//     // Write the packet to the pcap file
//      if (handlerData->pcapDumper != nullptr) {
//         pcap_dump(reinterpret_cast<u_char*>(handlerData->pcapDumper), pkthdr, packetData);
//     }
// //////////////////////////////////////////////////////////////////////////////

//     // Process the captured packet using SplitPacket to process the captured packet.
//     splitPacket.processPacket(packetData, pkthdr->len);


//       // Insert data into database (Extracts Ethernet and IPv4 data from the packet. Initializes vectors for TCP, UDP, ICMP, and GTP-U data)
//     std::vector<std::string> ethernetData = splitPacket.extractEthernetData(reinterpret_cast<const struct ethhdr*>(packetData));
//     std::vector<std::string> ipv4Data = splitPacket.extractIPv4Data(reinterpret_cast<const struct iphdr*>(packetData + sizeof(struct ethhdr)));
//     std::vector<std::string> tcpData, udpData, icmpData;// icmpv6Data, gtpuData, dnsData, igmpData, nbnsData, mdnsData, smbData, quicData;

//     // Checks if IPv4 data is empty. If so, exit the function because the packet is not an IPv4 packet.
//     if (ipv4Data.empty()) {
//         // Handle error or non-IPv4 packets
//         return;
//     }

//       // Extract header length
//     size_t headerLength = sizeof(struct ethhdr) + (ipv4Data[1].size() * sizeof(char));

//     // Use switch-case for protocol checks
//     std::string protocolString = ipv4Data[7]; //extract the string representing the protocol encapsulated in the IPv4 packet.
//     if (std::all_of(protocolString.begin(), protocolString.end(), ::isdigit)) {//check if all characters in protocol String are digits to ensure the string represents a valid protocol number
//         int protocol = std::stoi(protocolString);
//         switch (protovoid PacketCapture::handleTraffic(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
//     PacketHandlerData* handlerData = reinterpret_cast<PacketHandlerData*>(userData);
//     int delay = handlerData->delay;
//     // Retrieve Sqlite3Helper object
//     Sqlite3Helper* sqlite3Helper = handlerData->sqlite3Helper;

//     // Create an instance of SplitPacket to process the packet.
//     SplitPacket splitPacket;

//     ////////////////////////////////////////////////////////////////////////////////////
//     // Write the packet to the pcap file
//      if (handlerData->pcapDumper != nullptr) {
//         pcap_dump(reinterpret_cast<u_char*>(handlerData->pcapDumper), pkthdr, packetData);
//     }
// //////////////////////////////////////////////////////////////////////////////

//     // Process the captured packet using SplitPacket to process the captured packet.
//     splitPacket.processPacket(packetData, pkthdr->len);


//       // Insert data into database (Extracts Ethernet and IPv4 data from the packet. Initializes vectors for TCP, UDP, ICMP, and GTP-U data)
//     std::vector<std::string> ethernetData = splitPacket.extractEthernetData(reinterpret_cast<const struct ethhdr*>(packetData));
//     std::vector<std::string> ipv4Data = splitPacket.extractIPv4Data(reinterpret_cast<const struct iphdr*>(packetData + sizeof(struct ethhdr)));
//     std::vector<std::string> tcpData, udpData, icmpData;// icmpv6Data, gtpuData, dnsData, igmpData, nbnsData, mdnsData, smbData, quicData;

//     // Checks if IPv4 data is empty. If so, exit the function because the packet is not an IPv4 packet.
//     if (ipv4Data.empty()) {
//         // Handle error or non-IPv4 packets
//         return;
//     }

//       // Extract header length
//     size_t headerLength = sizeof(struct ethhdr) + (ipv4Data[1].size() * sizeof(char));

//     // Use switch-case for protocol checks
//     std::string protocolString = ipv4Data[7]; //extract the string representing the protocol encapsulated in the IPv4 packet.
//     if (std::all_of(protocolString.begin(), protocolString.end(), ::isdigit)) {//check if all characters in protocol String are digits to ensure the string represents a valid protocol number
//         int protocol = std::stoi(protocolString);
//         switch (protocol) {
//             case IPPROTO_TCP:
//                 std::cout << "Inserting TCP header data..." << std::endl;
//                 tcpData = splitPacket.extractTCPData(reinterpret_cast<const struct tcphdr*>(packetData + headerLength));
//                 if (tcpFields.size() == tcpData.size()) {
//                     sqlite3Helper->insert_into_table("tcp_header", tcpFields, tcpData);
//                 } else {
//                     std::cerr << "Error: Number of TCP fields doesn't match number of values!" << std::endl;
//                 }
//                 break;
//             case IPPROTO_UDP:
//                 std::cout << "Inserting UDP header data..." << std::endl;
//                 udpData = splitPacket.extractUDPData(reinterpret_cast<const struct udphdr*>(packetData + headerLength), pkthdr->len - headerLength);

//                 if (udpFields.size() == udpData.size()) {
//                     sqlite3Helper->insert_into_table("udp_header", udpFields, udpData);
//                 } else {
//                     std::cerr << "Error: Number of UDP fields doesn't match number of values!" << std::endl;
//                 }
//                 break;
//             case IPPROTO_ICMP:
//                 std::cout << "Inserting ICMP header data..." << std::endl;
//                 icmpData = splitPacket.extractICMPData(reinterpret_cast<const struct icmphdr*>(packetData + headerLength));
//                 if (icmpFields.size() == icmpData.size()) {
//                     sqlite3Helper->insert_into_table("icmp_header", icmpFields, icmpData);
//                 } else {
//                     std::cerr << "Error: Number of ICMP fields doesn't match number of values!" << std::endl;
//                 }
//                 break;
//             // Add cases for other protocols as needed
//         }
//     }
//  // Insert Ethernet and IPv4 data into the database
//     if (ethFields.size() == ethernetData.size()) {
//         sqlite3Helper->insert_into_table("eth_header", ethFields, ethernetData);
//     } else {
//         std::cerr << "Error: Number of Ethernet fields doesn't match number of values!" << std::endl;
//     }

//     if (ipv4Fields.size() == ipv4Data.size()) {
//         sqlite3Helper->insert_into_table("ipv4_header", ipv4Fields, ipv4Data);
//     } else {
//         std::cerr << "Error: Number of IPv4 fields doesn't match number of values!" << std::endl;
//     }
// col) {
//             case IPPROTO_TCP:
//                 std::cout << "Inserting TCP header data..." << std::endl;
//                 tcpData = splitPacket.extractTCPData(reinterpret_cast<const struct tcphdr*>(packetData + headerLength));
//                 if (tcpFields.size() == tcpData.size()) {
//                     sqlite3Helper->insert_into_table("tcp_header", tcpFields, tcpData);
//                 } else {
//                     std::cerr << "Error: Number of TCP fields doesn't match number of values!" << std::endl;
//                 }
//                 break;
//             case IPPROTO_UDP:
//                 std::cout << "Inserting UDP header data..." << std::endl;
//                 udpData = splitPacket.extractUDPData(reinterpret_cast<const struct udphdr*>(packetData + headerLength), pkthdr->len - headerLength);

//                 if (udpFields.size() == udpData.size()) {
//                     sqlite3Helper->insert_into_table("udp_header", udpFields, udpData);
//                 } else {
//                     std::cerr << "Error: Number of UDP fields doesn't match number of values!" << std::endl;
//                 }
//                 break;
//             case IPPROTO_ICMP:
//                 std::cout << "Inserting ICMP header data..." << std::endl;
//                 icmpData = splitPacket.extractICMPData(reinterpret_cast<const struct icmphdr*>(packetData + headerLength));
//                 if (icmpFields.size() == icmpData.size()) {
//                     sqlite3Helper->insert_into_table("icmp_header", icmpFields, icmpData);
//                 } else {
//                     std::cerr << "Error: Number of ICMP fields doesn't match number of values!" << std::endl;
//                 }
//                 break;
//             // Add cases for other protocols as needed
//         }
//     }
//  // Insert Ethernet and IPv4 data into the database
//     if (ethFields.size() == ethernetData.size()) {
//         sqlite3Helper->insert_into_table("eth_header", ethFields, ethernetData);
//     } else {
//         std::cerr << "Error: Number of Ethernet fields doesn't match number of values!" << std::endl;
//     }

//     if (ipv4Fields.size() == ipv4Data.size()) {
//         sqlite3Helper->insert_into_table("ipv4_header", ipv4Fields, ipv4Data);
//     } else {
//         std::cerr << "Error: Number of IPv4 fields doesn't match number of values!" << std::endl;
//     }
// }























// //Declares a method to handle Ethernet packets
// void PacketCapture::eth_handle(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
//     PacketHandlerData* handlerData = reinterpret_cast<PacketHandlerData*>(userData);//Converts user Data to a pointer to PacketHandler Data.
//     int delay = handlerData->delay;

//     // // Retrieve Sqlite3Helper object
//     // Sqlite3Helper* sqlite3Helper = handlerData->sqlite3Helper;

//     // Create an instance of SplitPacket to process the packet.
//     SplitPacket splitPacket;//This class is used to process captured packet data, such as extracting Ethernet and IPv4 headers.

//     // Write the packet to the pcap file
//      if (handlerData->pcapDumper != nullptr) {
//         pcap_dump(reinterpret_cast<u_char*>(handlerData->pcapDumper), pkthdr, packetData);
//     }

//     // Process the captured packet using SplitPacket to process the captured packet.
//     splitPacket.processPacket(packetData, pkthdr->len);//processPacket method of the splitPacket instance to process the captured packet data.


//       // Insert data into database (Extracts Ethernet and IPv4 data from the packet. Initializes vectors for TCP, UDP, ICMP, and GTP-U data)
//     std::vector<std::string> ethernetData = splitPacket.extractEthernetData(reinterpret_cast<const struct ethhdr*>(packetData));
//     std::vector<std::string> ipv4Data = splitPacket.extractIPv4Data(reinterpret_cast<const struct iphdr*>(packetData + sizeof(struct ethhdr)));
//     std::vector<std::string> tcpData, udpData, icmpData;// icmpv6Data, gtpuData, dnsData, igmpData, nbnsData, mdnsData, smbData, quicData;

//     // Checks if IPv4 data is empty. If so, exit the function because the packet is not an IPv4 packet.
//     if (ipv4Data.empty()) {//checks if the ipv4Data vector is empty by calling the empty() function
//         // Handle error or non-IPv4 packets
//         return;
//     }

//       // Extract header length
//     size_t headerLength = sizeof(struct ethhdr) + (ipv4Data[1].size() * sizeof(char));

//     // Use switch-case for protocol checks
//     std::string protocolString = ipv4Data[8]; //extract the string representing the protocol encapsulated in the IPv4 packet.
//     if (std::all_of(protocolString.begin(), protocolString.end(), ::isdigit)) {//check if all characters in protocol String are digits to ensure the string represents a valid protocol number
//         int protocol = std::stoi(protocolString);
//         switch (protocol) {
//             case IPPROTO_TCP:
//                 std::cout << "Inserting TCP header data..." << std::endl;
//                 tcpData = splitPacket.extractTCPData(reinterpret_cast<const struct tcphdr*>(packetData + headerLength));
//                 if (tcpFields.size() == tcpData.size()) {
//                     sqlite3Helper->insert_into_table("tcp_header", tcpFields, tcpData);
//                 } else {
//                     std::cerr << "Error: Number of TCP fields doesn't match number of values!" << std::endl;
//                 }
//                 break;
//             case IPPROTO_UDP:
//                 std::cout << "Inserting UDP header data..." << std::endl;
//                 udpData = splitPacket.extractUDPData(reinterpret_cast<const struct udphdr*>(packetData + headerLength), pkthdr->len - headerLength);

//                 if (udpFields.size() == udpData.size()) {
//                     sqlite3Helper->insert_into_table("udp_header", udpFields, udpData);
//                 } else {
//                     std::cerr << "Error: Number of UDP fields doesn't match number of values!" << std::endl;
//                 }
//                 break;
//             case IPPROTO_ICMP:
//                 std::cout << "Inserting ICMP header data..." << std::endl;
//                 icmpData = splitPacket.extractICMPData(reinterpret_cast<const struct icmphdr*>(packetData + headerLength));
//                 if (icmpFields.size() == icmpData.size()) {
//                     sqlite3Helper->insert_into_table("icmp_header", icmpFields, icmpData);
//                 } else {
//                     std::cerr << "Error: Number of ICMP fields doesn't match number of values!" << std::endl;
//                 }
//                 break;
//             // Add cases for other protocols as needed
//         }
//     }
//  // Insert Ethernet and IPv4 data into the database
//     if (ethFields.size() == ethernetData.size()) {
//         sqlite3Helper->insert_into_table("eth_header", ethFields, ethernetData);
//     } else {
//         std::cerr << "Error: Number of Ethernet fields doesn't match number of values!" << std::endl;
//     }

//     if (ipv4Fields.size() == ipv4Data.size()) {
//         sqlite3Helper->insert_into_table("ipv4_header", ipv4Fields, ipv4Data);
//     } else {
//         std::cerr << "Error: Number of IPv4 fields doesn't match number of values!" << std::endl;
//     }
// }





