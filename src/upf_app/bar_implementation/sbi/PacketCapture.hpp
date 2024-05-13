#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include <pcap.h>
#include <iostream>
#include "SplitPacket.hpp" // Include SplitPacket header

class PacketCapture {
public:
    static int capturePackets();
private:
    static int packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData);
};

#endif // PACKET_CAPTURE_HPP

 