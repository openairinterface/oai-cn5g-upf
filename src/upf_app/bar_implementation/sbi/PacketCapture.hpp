#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include "../database_code/Sqlite3Helper.hpp"
#include <pcap.h>
#include <iostream>

// struct PacketHandlerData {
//     int delay;
//     //Sqlite3Helper* sqlite3Helper;//Pointer to a Sqlite3Helper object to allow the package management function to insert data into the database.
//     pcap_dumper_t* pcapDumper;
/// };

class PacketCapture {
public:
    int capturePackets(int delay, pcap_dumper_t* pcapDumper); //// Function to capture packets with a specified delay and a pointer to a pcapDumper object used for writing captured packets to a capture file.
    
    pcap_dumper_t* getPcapDumper();//method that returns a pointer to the pcap_dumper_t object which is used to write captured packets to a file. This is an access method to get the pcap_dumper_t object.
    
    
    pcap_dumper_t* pcapDumper;//It is a member of the Packet Capture class that stores the pointer to the pcap_dumper_t object.


private:
//// Static function to process captured packets. It is called every time a packet is captured to process it
    static void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData);
    
    int delay;
    
};

#endif // PACKET_CAPTURE_HPP
