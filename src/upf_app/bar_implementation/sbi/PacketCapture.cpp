#include "PacketCapture.hpp"
#include "PacketSplit.hpp"
#include "../database_code/Sqlite3Helper.hpp"
#include <pcap.h>
#include <iostream>
#include "../include/headers.hpp"
#include <algorithm>




pcap_t* open_pcap(const char *interface){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Open the interface for packet capturing
    if (not (handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)){
        std::cerr << "Error opening interface %s: " << interface << errbuf << std::endl;
    }
    return handle;
}

/*-------------------------------------------------------------------------------------*/
pcap_dumper_t* getPcapDumper(){
    return pcapDumper;
}

/*------------------------------------------------------------------------------------*/
void setPcapDumper(pcap_dumper_t* pcap){
    pcapDumper = pcap;
}

/*------------------------------------------------------------------------------------*/
int PacketCapture::capturePackets(pcap_t* handle, int delay, pcap_dumper_t* pcapDumper, char* interface) {    
    // // Open a pcap file for writing
    // if (pcapDumper == nullptr) {
    //     std::cerr << "Error opening output file." << std::endl;
    //     pcap_close(handle);
    //     return -1;
    // }

    // // Structure to pass delay to packetHandler
    // PacketHandlerData handlerData = {delay, pcapDumper};

    // Start capturing packets           
//int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);                   
    pcap_loop(handle, 1, packetHandler, reinterpret_cast<u_char*>(&handlerData)); // Pass pcapDumper

    // Close the interface
    pcap_close(handle);
    return 0;
}


// int PacketCapture::capturePackets(pcap_t* handle, int delay, pcap_dumper_t* pcapDumper, char* interface) {    
//     // Open a pcap file for writing
//     if (pcapDumper == nullptr) {
//         std::cerr << "Error opening output file." << std::endl;
//         pcap_close(handle);
//         return -1;
//     }

//     // Structure to pass delay to packetHandler
//     PacketHandlerData handlerData = {delay, pcapDumper};

//     // Start capturing packets                                    
//     pcap_loop(handle, 1, packetHandler, reinterpret_cast<u_char*>(&handlerData)); // Pass pcapDumper

//     // Close the interface
//     pcap_close(handle);
//     return 0;
// }



void PacketCapture::eth_handle(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    PacketHandlerData* handlerData = reinterpret_cast<PacketHandlerData*>(userData);
    int delay = handlerData->delay;

    // // Retrieve Sqlite3Helper object
    // Sqlite3Helper* sqlite3Helper = handlerData->sqlite3Helper;

    // Create an instance of SplitPacket to process the packet.
    SplitPacket splitPacket;

    // Write the packet to the pcap file
     if (handlerData->pcapDumper != nullptr) {
        pcap_dump(reinterpret_cast<u_char*>(handlerData->pcapDumper), pkthdr, packetData);
    }

    // Process the captured packet using SplitPacket to process the captured packet.
    splitPacket.processPacket(packetData, pkthdr->len);


      // Insert data into database (Extracts Ethernet and IPv4 data from the packet. Initializes vectors for TCP, UDP, ICMP, and GTP-U data)
    std::vector<std::string> ethernetData = splitPacket.extractEthernetData(reinterpret_cast<const struct ethhdr*>(packetData));
    std::vector<std::string> ipv4Data = splitPacket.extractIPv4Data(reinterpret_cast<const struct iphdr*>(packetData + sizeof(struct ethhdr)));
    std::vector<std::string> tcpData, udpData, icmpData;// icmpv6Data, gtpuData, dnsData, igmpData, nbnsData, mdnsData, smbData, quicData;

    // Checks if IPv4 data is empty. If so, exit the function because the packet is not an IPv4 packet.
    if (ipv4Data.empty()) {
        // Handle error or non-IPv4 packets
        return;
    }

      // Extract header length
    size_t headerLength = sizeof(struct ethhdr) + (ipv4Data[1].size() * sizeof(char));

    // Use switch-case for protocol checks
    std::string protocolString = ipv4Data[7]; //extract the string representing the protocol encapsulated in the IPv4 packet.
    if (std::all_of(protocolString.begin(), protocolString.end(), ::isdigit)) {//check if all characters in protocol String are digits to ensure the string represents a valid protocol number
        int protocol = std::stoi(protocolString);
        switch (protocol) {
            case IPPROTO_TCP:
                std::cout << "Inserting TCP header data..." << std::endl;
                tcpData = splitPacket.extractTCPData(reinterpret_cast<const struct tcphdr*>(packetData + headerLength));
                if (tcpFields.size() == tcpData.size()) {
                    sqlite3Helper->insert_into_table("tcp_header", tcpFields, tcpData);
                } else {
                    std::cerr << "Error: Number of TCP fields doesn't match number of values!" << std::endl;
                }
                break;
            case IPPROTO_UDP:
                std::cout << "Inserting UDP header data..." << std::endl;
                udpData = splitPacket.extractUDPData(reinterpret_cast<const struct udphdr*>(packetData + headerLength), pkthdr->len - headerLength);

                if (udpFields.size() == udpData.size()) {
                    sqlite3Helper->insert_into_table("udp_header", udpFields, udpData);
                } else {
                    std::cerr << "Error: Number of UDP fields doesn't match number of values!" << std::endl;
                }
                break;
            case IPPROTO_ICMP:
                std::cout << "Inserting ICMP header data..." << std::endl;
                icmpData = splitPacket.extractICMPData(reinterpret_cast<const struct icmphdr*>(packetData + headerLength));
                if (icmpFields.size() == icmpData.size()) {
                    sqlite3Helper->insert_into_table("icmp_header", icmpFields, icmpData);
                } else {
                    std::cerr << "Error: Number of ICMP fields doesn't match number of values!" << std::endl;
                }
                break;
            // Add cases for other protocols as needed
        }
    }
 // Insert Ethernet and IPv4 data into the database
    if (ethFields.size() == ethernetData.size()) {
        sqlite3Helper->insert_into_table("eth_header", ethFields, ethernetData);
    } else {
        std::cerr << "Error: Number of Ethernet fields doesn't match number of values!" << std::endl;
    }

    if (ipv4Fields.size() == ipv4Data.size()) {
        sqlite3Helper->insert_into_table("ipv4_header", ipv4Fields, ipv4Data);
    } else {
        std::cerr << "Error: Number of IPv4 fields doesn't match number of values!" << std::endl;
    }
}







void PacketCapture::packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    PacketHandlerData* handlerData = reinterpret_cast<PacketHandlerData*>(userData);
    int delay = handlerData->delay;
    // Retrieve Sqlite3Helper object
    Sqlite3Helper* sqlite3Helper = handlerData->sqlite3Helper;

    // Create an instance of SplitPacket to process the packet.
    SplitPacket splitPacket;

    ////////////////////////////////////////////////////////////////////////////////////
    // Write the packet to the pcap file
     if (handlerData->pcapDumper != nullptr) {
        pcap_dump(reinterpret_cast<u_char*>(handlerData->pcapDumper), pkthdr, packetData);
    }
//////////////////////////////////////////////////////////////////////////////

    // Process the captured packet using SplitPacket to process the captured packet.
    splitPacket.processPacket(packetData, pkthdr->len);


      // Insert data into database (Extracts Ethernet and IPv4 data from the packet. Initializes vectors for TCP, UDP, ICMP, and GTP-U data)
    std::vector<std::string> ethernetData = splitPacket.extractEthernetData(reinterpret_cast<const struct ethhdr*>(packetData));
    std::vector<std::string> ipv4Data = splitPacket.extractIPv4Data(reinterpret_cast<const struct iphdr*>(packetData + sizeof(struct ethhdr)));
    std::vector<std::string> tcpData, udpData, icmpData;// icmpv6Data, gtpuData, dnsData, igmpData, nbnsData, mdnsData, smbData, quicData;

    // Checks if IPv4 data is empty. If so, exit the function because the packet is not an IPv4 packet.
    if (ipv4Data.empty()) {
        // Handle error or non-IPv4 packets
        return;
    }

      // Extract header length
    size_t headerLength = sizeof(struct ethhdr) + (ipv4Data[1].size() * sizeof(char));

    // Use switch-case for protocol checks
    std::string protocolString = ipv4Data[7]; //extract the string representing the protocol encapsulated in the IPv4 packet.
    if (std::all_of(protocolString.begin(), protocolString.end(), ::isdigit)) {//check if all characters in protocol String are digits to ensure the string represents a valid protocol number
        int protocol = std::stoi(protocolString);
        switch (protocol) {
            case IPPROTO_TCP:
                std::cout << "Inserting TCP header data..." << std::endl;
                tcpData = splitPacket.extractTCPData(reinterpret_cast<const struct tcphdr*>(packetData + headerLength));
                if (tcpFields.size() == tcpData.size()) {
                    sqlite3Helper->insert_into_table("tcp_header", tcpFields, tcpData);
                } else {
                    std::cerr << "Error: Number of TCP fields doesn't match number of values!" << std::endl;
                }
                break;
            case IPPROTO_UDP:
                std::cout << "Inserting UDP header data..." << std::endl;
                udpData = splitPacket.extractUDPData(reinterpret_cast<const struct udphdr*>(packetData + headerLength), pkthdr->len - headerLength);

                if (udpFields.size() == udpData.size()) {
                    sqlite3Helper->insert_into_table("udp_header", udpFields, udpData);
                } else {
                    std::cerr << "Error: Number of UDP fields doesn't match number of values!" << std::endl;
                }
                break;
            case IPPROTO_ICMP:
                std::cout << "Inserting ICMP header data..." << std::endl;
                icmpData = splitPacket.extractICMPData(reinterpret_cast<const struct icmphdr*>(packetData + headerLength));
                if (icmpFields.size() == icmpData.size()) {
                    sqlite3Helper->insert_into_table("icmp_header", icmpFields, icmpData);
                } else {
                    std::cerr << "Error: Number of ICMP fields doesn't match number of values!" << std::endl;
                }
                break;
            // Add cases for other protocols as needed
        }
    }
 // Insert Ethernet and IPv4 data into the database
    if (ethFields.size() == ethernetData.size()) {
        sqlite3Helper->insert_into_table("eth_header", ethFields, ethernetData);
    } else {
        std::cerr << "Error: Number of Ethernet fields doesn't match number of values!" << std::endl;
    }

    if (ipv4Fields.size() == ipv4Data.size()) {
        sqlite3Helper->insert_into_table("ipv4_header", ipv4Fields, ipv4Data);
    } else {
        std::cerr << "Error: Number of IPv4 fields doesn't match number of values!" << std::endl;
    }
}
        //case IPPROTO_ICMPV6:
            //icmpv6Data = splitPacket.extractICMPv6Data(reinterpret_cast<const struct icmp6_hdr*>(packetData + headerLength));
            //break;
        //case IPPROTO_IGMP:
            //igmpData = splitPacket.extractIGMPData(reinterpret_cast<const struct igmp*>(packetData + headerLength));
            //break;
        //case IPPROTO_DNS:
            //dnsData = splitPacket.extractDNSData(reinterpret_cast<const struct dnshdr*>(packetData + headerLength));
            //break;
        //case IPPROTO_NBNS:
            //nbnsData = splitPacket.extractNBNSData(reinterpret_cast<const struct nbns*>(packetData + headerLength));
            //break;
        //case IPPROTO_MDNS:
            //mdnsData = splitPacket.extractMDNSData(reinterpret_cast<const struct mdns*>(packetData + headerLength));
            //break;
        //case IPPROTO_SMB:
            //smbData = splitPacket.extractSMBData(reinterpret_cast<const struct smb*>(packetData + headerLength));
            //break;
        //case IPPROTO_QUIC:
            //quicData = splitPacket.extractQUICData(reinterpret_cast<const struct quic*>(packetData + headerLength));
            //break;
        //default:
            // Handle other protocols or unknown protocols
            //break;
  //  }
//}

    // Insert the extracted data into the appropriate tables in the database using sqlite3Helper                              
    //sqlite3Helper->insert_into_table("eth_header", ethFields, ethernetData);
    // sqlite3Helper->insert_into_table("ipv4_header", ipv4Fields, ipv4Data);
    // sqlite3Helper->insert_into_table("tcp_header", tcpFields, tcpData);
    // sqlite3Helper->insert_into_table("udp_header", udpFields, udpData);
    // sqlite3Helper->insert_into_table("icmp_header", icmpFields, icmpData);
    // sqlite3Helper->insert_into_table("icmpv6_header", icmpv6Fields, icmpv6Data);
    // sqlite3Helper->insert_into_table("gtpu_header", gtpuFields, gtpuData);
    // sqlite3Helper->insert_into_table("dns_header", dnsFields, dnsData);
    //sqlite3Helper->insert_into_table("igmp_header", igmpFields, igmpData);
    //sqlite3Helper->insert_into_table("nbns_header", nbnsFields, nbnsData);
    //sqlite3Helper->insert_into_table("mdns_header", mdnsFields, mdnsData);
    //sqlite3Helper->insert_into_table("smb_header", smbFields, smbData);
    //sqlite3Helper->insert_into_table("quic_header", quicFields, quicData);

    // Start the alert timer with the specified delay
    //Trigger trigger(delay);
    //trigger.startAlertTimer();
//}