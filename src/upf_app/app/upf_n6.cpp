
#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "upf_config.hpp"
#include "upf_n6.hpp"
#include "pfcp_switch.hpp"

#include <chrono>
#include <ctime>
#include <stdexcept>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>

#include<sys/types.h>
#include<sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/ether.h> // for ether_ntoa()
#include "nsh.h"

using namespace oai::upf::app;
using namespace oai::config;
using namespace std;

extern itti_mw* itti_inst;
extern upf_config upf_cfg;
extern upf_n6* upf_n6_inst;
extern pfcp_switch* pfcp_switch_inst;

//------------------------------------------------------------------------------
upf_n6::upf_n6()
    : raw_s(raw_server(upf_cfg.n6.if_name.c_str())) {
  Logger::upf_n6().info(
      "upf_n6 created listening to %s",
      inet_ntoa(upf_cfg.n6.addr4));

  id = 0;
  raw_s.start_receive(this, upf_cfg.n6.thread_rd_sched_params);
  Logger::upf_n6().startup("Started");
}

//------------------------------------------------------------------------------
void upf_n6::handle_receive(
    const char* recv_buffer, const std::size_t bytes_transferred) {

    struct ethhdr* eth = (struct ethhdr*) recv_buffer;
    if (ntohs(eth->h_proto) == ETH_P_NSH) { // Check if it's NSH packet
        // Handle NSH packet
        Logger::upf_n6().error("NSH logic not implemented");
    } else if (ntohs(eth->h_proto) == ETH_P_IP || ntohs(eth->h_proto) == ETH_P_IPV6) { // Check if IP packet
        // Send depending on IP version
        if (ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr* iph = (struct iphdr*)(recv_buffer + sizeof(struct ethhdr));
    
            // TODO [TS-SFC] Config socket to only read incoming packets
            if (iph->saddr != upf_cfg.n6.addr4.s_addr) {
                pfcp_switch_inst->pfcp_session_look_up_pack_in_n6_lan(iph, bytes_transferred - sizeof(struct ethhdr));
            }
        } 
        else {
            struct ipv6hdr* iph = (struct ipv6hdr*)(recv_buffer + sizeof(struct ethhdr));
            pfcp_switch_inst->pfcp_session_look_up_pack_in_n6_lan(iph, bytes_transferred - sizeof(struct ethhdr));
        }
    } else {
         Logger::upf_n6().debug("Received unkwown packet");
    }

}

void upf_n6::send_to_n6(char* ip_packet, const ssize_t len) {

    size_t buffer_size = sizeof(struct ethhdr) + len;
    char* buffer = new char[buffer_size];

    struct ethhdr* ethhdr = reinterpret_cast<struct ethhdr*>(buffer);
    memset(ethhdr, 0, sizeof(struct ethhdr));

    // Set the MAC
    const char* srcMacEnv = getenv("N6_MAC");
    const char* destMacEnv = getenv("LAN_MAC");
    struct ether_addr *mac = ether_aton(srcMacEnv);
    memcpy(ethhdr->h_source, mac->ether_addr_octet, ETH_ALEN);

    mac = ether_aton(destMacEnv);
    memcpy(ethhdr->h_dest, mac->ether_addr_octet, ETH_ALEN);

    ethhdr->h_proto = htons(ETH_P_IP);

    memcpy(buffer + sizeof(struct ethhdr), ip_packet, len);  

    raw_s.send(buffer, buffer_size);

    delete[] buffer; // Clean up
}

void upf_n6::send_nsh(char* ip_packet, const ssize_t len, uint32_t spi, uint32_t si) {
    // This function sends an MD TYPE 2 NSH header without any metadata.
    int nshhdr_len = (2 << 2);
    size_t buffer_size = sizeof(struct ethhdr) + nshhdr_len + len;
    char* buffer = new char[buffer_size];

    struct ethhdr* ethhdr = reinterpret_cast<struct ethhdr*>(buffer);
    memset(ethhdr, 0, sizeof(struct ethhdr));

    // Set the MAC
    const char* srcMacEnv = getenv("N6_MAC");
    const char* destMacEnv = getenv("LAN_MAC");
    struct ether_addr *mac = ether_aton(srcMacEnv);
    memcpy(ethhdr->h_source, mac->ether_addr_octet, ETH_ALEN);

    mac = ether_aton(destMacEnv);
    memcpy(ethhdr->h_dest, mac->ether_addr_octet, ETH_ALEN);

    ethhdr->h_proto = htons(ETH_P_NSH);

    // Set NSH
    struct nshhdr* nshhdr = reinterpret_cast<struct nshhdr*>(buffer + sizeof(struct ethhdr));
    memset(nshhdr, 0, sizeof(struct nshhdr));
    nshhdr->ver_flags_ttl_len = 0;
    nshhdr->mdtype          = 2;
    nshhdr->np              = 0x01;
    nshhdr->path_hdr             = 0x11220101;
    nsh_set_flags_ttl_len(nshhdr, 0x0, 0x3F, (2 << 2));

    memcpy(buffer + sizeof(struct ethhdr) + nshhdr_len, ip_packet, len);  

    raw_s.send(buffer, buffer_size);

    delete[] buffer; // Clean up
}

void upf_n6::send_nsh(char* ip_packet, const ssize_t len, uint32_t spi, uint32_t si,
    char* metdata, const ssize_t metadata_len) {
    int nshhdr_len = (2 << 2) + metadata_len;
    size_t buffer_size = sizeof(struct ethhdr) + nshhdr_len + len;
    char* buffer = new char[buffer_size];

    struct ethhdr* ethhdr = reinterpret_cast<struct ethhdr*>(buffer);
    memset(ethhdr, 0, sizeof(struct ethhdr));

    // Set the MAC
    const char* srcMacEnv = getenv("N6_MAC");
    const char* destMacEnv = getenv("LAN_MAC");
    struct ether_addr *mac = ether_aton(srcMacEnv);
    memcpy(ethhdr->h_source, mac->ether_addr_octet, ETH_ALEN);

    mac = ether_aton(destMacEnv);
    memcpy(ethhdr->h_dest, mac->ether_addr_octet, ETH_ALEN);

    ethhdr->h_proto = htons(ETH_P_NSH);

    // Set NSH 
    struct nshhdr* nshhdr = reinterpret_cast<struct nshhdr*>(buffer + sizeof(struct ethhdr));
    memset(nshhdr, 0, sizeof(struct nshhdr));
    nshhdr->ver_flags_ttl_len = 0;
    nshhdr->mdtype          = 2;
    nshhdr->np              = 0x01;
    nshhdr->path_hdr        = ((spi << NSH_SPI_SHIFT) & NSH_SPI_MASK) |
			     ((si << NSH_SI_SHIFT) & NSH_SI_MASK);
    memcpy(&nshhdr->md2, metdata, metadata_len);
    nsh_set_flags_ttl_len(nshhdr, 0x0, 0x3F, nshhdr_len);

    memcpy(buffer + sizeof(struct ethhdr) + nshhdr_len, ip_packet, len);  

    raw_s.send(buffer, buffer_size);

    delete[] buffer; // Clean up
}

// TODO [TS-SFC] support IPv6

// TODO [TS-SFC] Update udp.hpp to add room to the buffer for encapsulation
// void upf_n6::send_nsh(char* ip_packet, const ssize_t len) {
//     struct ethhdr* ethhdr = reinterpret_cast<struct ethhdr*>(
//         reinterpret_cast<uintptr_t>(ip_packet) -
//         (uintptr_t) sizeof(struct ethhdr) -
//         (uintptr_t) sizeof(struct nshhdr));

//     memset(ethhdr, 0, sizeof(struct ethhdr));

//     struct nshhdr* nshhdr =
//         reinterpret_cast<struct nshhdr*>(
//             reinterpret_cast<uintptr_t>(ip_packet) -
//             (uintptr_t) sizeof(struct nshhdr));

//     memset(nshhdr, 0, sizeof(struct nshhdr));

//     raw_s.send(reinterpret_cast<const char*>(ethhdr), len + sizeof(struct ethhdr) + sizeof(struct nshhdr));
// }