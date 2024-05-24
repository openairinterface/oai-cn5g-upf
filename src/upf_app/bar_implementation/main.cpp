#include "sbi/DatabaseManager.hpp"
#include "sbi/PacketCapture.hpp"
#include "sbi/include/headers.hpp"
#include <iostream>
#include <pcap.h>

int main() {
    // Get the unique instance of the database manager
    DatabaseManager& dbManager = DatabaseManager::getInstance();
    
    // Get a reference to the instance of Sqlite3Helper
    std::unique_ptr<Sqlite3Helper> sqlite3Helper = dbManager.createSqlite3Helper();

    std::string db_name = "Buffer";
    int rc = 0;

    // Create the database
    rc = sqlite3Helper->create_database(db_name);  

     // Create tables
         if (!rc) {
        if (sqlite3Helper->create_table("eth_header", ethFields) == SQLITE_OK) {
            std::cout << "Ethernet Header table created successfully." << std::endl;
        } else {
            std::cerr << "Error creating Ethernet Header table." << std::endl;
        }
        
        if (sqlite3Helper->create_table("ipv4_header", ipv4Fields) == SQLITE_OK) {
            std::cout << "IPv4 Header table created successfully." << std::endl;
        } else {
            std::cerr << "Error creating IPv4 Header table." << std::endl;
        }

        if (sqlite3Helper->create_table("tcp_header", tcpFields) == SQLITE_OK) {
            std::cout << "TCP Header table created successfully." << std::endl;
        } else {
            std::cerr << "Error creating TCP Header table." << std::endl;
        }

        if (sqlite3Helper->create_table("udp_header", udpFields) == SQLITE_OK) {
            std::cout << "UDP Header table created successfully." << std::endl;
        } else {
            std::cerr << "Error creating UDP Header table." << std::endl;
        }

        if (sqlite3Helper->create_table("icmp_header", icmpFields) == SQLITE_OK) {
            std::cout << "ICMP Header table created successfully." << std::endl;
        } else {
            std::cerr << "Error creating ICMP Header table." << std::endl;
        }
    }
         
    
     // Create the IPv4 Header table
    //rc = sqlite3Helper->create_table("ipv4_header", ipv4Fields);
    // Create the TCP Header table
    //if (!rc)
        //rc = sqlite3Helper->create_table("tcp_header", tcpFields);
    // Create the UDP Header table
    //if (!rc) 
        //rc = sqlite3Helper->create_table("udp_header", udpFields);
    // Create the ICMP Header table
    //if (!rc)
        // rc = sqlite3Helper->create_table("icmp_header", icmpFields);
    // Create the ICMPv6 Header table
    //if (!rc)
        //rc = sqlite3Helper->create_table("icmpv6_header", icmpv6Fields);
    // Create the DNS Header table
    //if (!rc)
        //rc = sqlite3Helper->create_table("dns_header", dnsFields);
    // Create the IGMP Header table
    //if (!rc)
        //rc = sqlite3Helper->create_table("igmp_header", igmpFields);
    // Create the NBNS Header table
    //if (!rc)
        //rc = sqlite3Helper->create_table("nbns_header", nbnsFields);
    // Create the mDNS Header table
    //if (!rc)
        //rc = sqlite3Helper->create_table("mdns_header", mdnsFields);
    // Create the SMB Header table
    //if (!rc)
        //rc = sqlite3Helper->create_table("smb_header", smbFields);
    // Create the QUIC Header table
    //if (!rc)
        //rc = sqlite3Helper->create_table("quic_header", quicFields);
    //Create the GTPU table
    //if(!rc) 
        //rc = sqlite3Helper->create_table("gtpu", gtpuFields);
    // Create the Data table
   // if (!rc)
        //rc = sqlite3Helper->create_table("data_header", dataFields);

    // Check if tables are created successfully
    if (rc) {
        std::cerr << "Error creating tables." << std::endl;
        return -1;
    }

    // Open the pcap file for writing
    const char* pcapFilename = "captured_packets.pcap";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap) {
        std::cerr << "Erreur lors de l'ouverture du fichier PCAP : " << pcapFilename << std::endl;
        return -1;
    }

    // Open the pcap dump file
    pcap_dumper_t* pcapDumper = pcap_dump_open(pcap, pcapFilename);
    if (!pcapDumper) {
        std::cerr << "Erreur lors de l'ouverture du fichier PCAP pour écriture." << std::endl;
        return -1;
    }

    // Capture packets and write to pcap file
    int delay = 30; 
    PacketCapture packetCapture;
    packetCapture.capturePackets(delay, *sqlite3Helper, pcapDumper);

    // Close the pcap dump file and pcap handler
    pcap_dump_close(pcapDumper);
    pcap_close(pcap);

    return 0; // Return 0 to indicate successful execution
}
