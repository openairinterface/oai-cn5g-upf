#include "PacketCapture.hpp"
#include "Trigger.hpp"
#include <pcap.h>
#include <iostream>
#include <ctime>

int PacketCapture::capturePackets() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Open the interface for packet capturing
    handle = pcap_open_live("wlp0s20f3", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening interface: " << errbuf << std::endl;
        return -1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, reinterpret_cast<pcap_handler>(packetHandler), nullptr);

    // Close the interface
    pcap_close(handle);
    return 0;
}

int PacketCapture::packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    // This function will be called each time a packet is captured
    std::time_t now = std::time(nullptr);
    std::cout << "Packet received, size: " << pkthdr->len << " bytes, timestamp: " << std::ctime(&now);

    // Process the captured packet using SplitPacket
    SplitPacket::processPacket(packetData, pkthdr->len);

    // Start the alert timer
    Trigger trigger;
    trigger.startAlertTimer();
    return 0;
}
