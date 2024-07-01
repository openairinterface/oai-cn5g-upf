#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include <pcap.h>
#include <iostream>


class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();
    int captureTraffic(const char* interface, int packetCount, int delay, const char* filterExpr = nullptr); 
    pcap_dumper_t* getPcapDumper();
    void setPcapDumper(pcap_dumper_t* pcap);
    pcap_dumper_t* pcapDumper;


private:
    pcap_t* open_pcap(const char *interface);
    static void handleTraffic(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    int delay;

    struct HandlerData {
        // Add relevant fields here
    } handlerData;
    
};

#endif // PACKET_CAPTURE_HPP
