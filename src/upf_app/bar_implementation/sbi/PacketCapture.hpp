#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include "../database_code/Sqlite3Helper.hpp"
#include <pcap.h>
#include <iostream>

struct PacketHandlerData {
    int delay;
    Sqlite3Helper* sqlite3Helper;//Pointer to a Sqlite3Helper object to allow the package management function to insert data into the database.
    pcap_dumper_t* pcapDumper;
};

class PacketCapture {
public:
    int capturePackets(int delay, Sqlite3Helper& sqlite3Helper, pcap_dumper_t* pcapDumper); // Reference to a Sqlite3Helper object to interact with the database.

private:
    static void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData);
};

#endif // PACKET_CAPTURE_HPP
