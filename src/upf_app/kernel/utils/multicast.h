#ifndef BPF_MULTICAST_H
#define BPF_MULTICAST_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <types.h>
#include <stdint.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <utils/logger.h>

// Helper function to check IEEE 802 group multicast addresses
static inline bool is_ieee_802_multicast(
    const unsigned char* dest, const void* data_end, uint16_t ethertype) {
  // Check bounds for all 6 bytes of MAC address
  if (dest + 5 >= (unsigned char*) data_end) return false;

  // Check if first 3 bytes match 01-80-C2
  if (dest[0] != 0x01 || dest[1] != 0x80 || dest[2] != 0xC2) return false;

  // IEEE 802.1D Spanning Tree Protocol - 01-80-C2-00-00-00
  if (dest[3] == 0x00 && dest[4] == 0x00 && dest[5] == 0x00) {
    bpf_debug("Detected IEEE 802.1D STP multicast (01-80-C2-00-00-00)");
    return true;
  }

  // Flow control - 01-80-C2-00-00-01
  if (dest[3] == 0x00 && dest[4] == 0x00 && dest[5] == 0x01 &&
      ethertype == bpf_htons(0x8808)) {
    bpf_debug(
        "Detected IEEE 802.3x Flow Control multicast (01-80-C2-00-00-01)");
    return true;
  }

  // Slow protocols - 01-80-C2-00-00-02
  if (dest[3] == 0x00 && dest[4] == 0x00 && dest[5] == 0x02 &&
      ethertype == bpf_htons(0x8809)) {
    bpf_debug("Detected IEEE Slow Protocols multicast (01-80-C2-00-00-02)");
    return true;
  }

  // EAPOL - 01-80-C2-00-00-03
  if (dest[3] == 0x00 && dest[4] == 0x00 && dest[5] == 0x03 &&
      (ethertype == bpf_htons(0x888E) || ethertype == bpf_htons(0x88CC))) {
    bpf_debug("Detected IEEE 802.1X EAPOL multicast (01-80-C2-00-00-03)");
    return true;
  }

  // LLDP primary - 01-80-C2-00-00-0E
  if (dest[3] == 0x00 && dest[4] == 0x00 && dest[5] == 0x0E &&
      (ethertype == bpf_htons(0x88CC) || ethertype == bpf_htons(0x88F7))) {
    bpf_debug("Detected LLDP primary multicast (01-80-C2-00-00-0E)");
    return true;
  }

  // Provider bridges STP - 01-80-C2-00-00-08
  if (dest[3] == 0x00 && dest[4] == 0x00 && dest[5] == 0x08) {
    bpf_debug("Detected Provider Bridges STP multicast (01-80-C2-00-00-08)");
    return true;
  }

  // MVRP - 01-80-C2-00-00-0D
  if (dest[3] == 0x00 && dest[4] == 0x00 && dest[5] == 0x0D &&
      ethertype == bpf_htons(0x88F5)) {
    bpf_debug("Detected MVRP multicast (01-80-C2-00-00-0D)");
    return true;
  }

  // GVRP - 01-80-C2-00-00-21
  if (dest[3] == 0x00 && dest[4] == 0x00 && dest[5] == 0x21 &&
      ethertype == bpf_htons(0x88F5)) {
    bpf_debug("Detected GVRP/MVRP multicast (01-80-C2-00-00-21)");
    return true;
  }

  // Ethernet CFM - 01-80-C2-00-00-3x
  if (dest[3] == 0x00 && dest[4] == 0x00 &&
      (dest[5] >= 0x30 && dest[5] <= 0x3F) && ethertype == bpf_htons(0x8902)) {
    bpf_debug(
        "Detected Ethernet CFM multicast, specific: 01-80-C2-00-00-%02x",
        dest[5]);
    return true;
  }

  return false;
}

// Helper function to check IEEE TC9 PTP multicast address
static inline bool is_ieee_tc9_multicast(
    const unsigned char* dest, const void* data_end, uint16_t ethertype) {
  if (dest + 5 >= (unsigned char*) data_end) return false;

  if (dest[0] == 0x01 && dest[1] == 0x1B && dest[2] == 0x19 &&
      dest[3] == 0x00 && dest[4] == 0x00 && dest[5] == 0x00 &&
      ethertype == bpf_htons(0x88F7)) {
    bpf_debug("Detected IEEE TC9 PTP multicast (01-1B-19-00-00-00)");
    return true;
  }
  return false;
}

// Helper function to check IPv4 multicast addresses
static inline bool is_ipv4_multicast(
    const unsigned char* dest, const void* data_end, uint16_t ethertype) {
  if (dest + 5 >= (unsigned char*) data_end) return false;

  if (dest[0] == 0x01 && dest[1] == 0x00 && dest[2] == 0x5E &&
      (dest[3] & 0x80) == 0 &&  // Top bit must be 0 (0-7F range)
      ethertype == bpf_htons(0x0800)) {
    bpf_debug(
        "Detected IPv4 multicast: %02x:%02x:%02x", dest[0], dest[1], dest[2]);
    bpf_debug(
        "IPv4 multicast (cont): %02x:%02x:%02x", dest[3], dest[4], dest[5]);
    return true;
  }
  return false;
}

// Helper function to check IPv6 multicast addresses
static inline bool is_ipv6_multicast(
    const unsigned char* dest, const void* data_end, uint16_t ethertype) {
  if (dest + 5 >= (unsigned char*) data_end) return false;

  if (dest[0] == 0x33 && dest[1] == 0x33 && ethertype == bpf_htons(0x86DD)) {
    bpf_debug(
        "Detected IPv6 multicast: %02x:%02x:%02x", dest[0], dest[1], dest[2]);
    bpf_debug(
        "IPv6 multicast (cont): %02x:%02x:%02x", dest[3], dest[4], dest[5]);
    return true;
  }
  return false;
}

// Helper function to check IEC multicast addresses
static inline bool is_iec_multicast(
    const unsigned char* dest, const void* data_end, uint16_t ethertype) {
  if (dest + 5 >= (unsigned char*) data_end) return false;

  if (dest[0] != 0x01 || dest[1] != 0x0C || dest[2] != 0xCD) return false;

  // GOOSE Type 1/1A
  if (dest[3] == 0x01 && (dest[4] <= 0x01) && ethertype == bpf_htons(0x88B8)) {
    bpf_debug(
        "Detected IEC GOOSE multicast: %02x:%02x:%02x", dest[0], dest[1],
        dest[2]);
    bpf_debug(
        "IEC GOOSE multicast (cont): %02x:%02x:%02x", dest[3], dest[4],
        dest[5]);
    return true;
  }

  // GSSE
  if (dest[3] == 0x02 && (dest[4] <= 0x01) && ethertype == bpf_htons(0x88B9)) {
    bpf_debug(
        "Detected IEC GSSE multicast: %02x:%02x:%02x", dest[0], dest[1],
        dest[2]);
    bpf_debug(
        "IEC GSSE multicast (cont): %02x:%02x:%02x", dest[3], dest[4], dest[5]);
    return true;
  }

  // Multicast sampled values
  if (dest[3] == 0x04 && (dest[4] <= 0x01) && ethertype == bpf_htons(0x88BA)) {
    bpf_debug(
        "Detected IEC sampled values: %02x:%02x:%02x", dest[0], dest[1],
        dest[2]);
    bpf_debug(
        "IEC sampled values (cont): %02x:%02x:%02x", dest[3], dest[4], dest[5]);
    return true;
  }

  return false;
}

// Helper function to check Cisco multicast addresses
static inline bool is_cisco_multicast(
    const unsigned char* dest, const void* data_end) {
  if (dest + 5 >= (unsigned char*) data_end) return false;

  if (dest[0] != 0x01 || dest[1] != 0x00 || dest[2] != 0x0C) return false;

  // CDP, VTP, UDLD
  if (dest[3] == 0xCC && dest[4] == 0xCC && dest[5] == 0xCC) {
    bpf_debug("Detected Cisco CDP/VTP/UDLD multicast (01-00-0C-CC-CC-CC)");
    return true;
  }

  // Cisco Shared STP
  if (dest[3] == 0xCC && dest[4] == 0xCC && dest[5] == 0xCD) {
    bpf_debug("Detected Cisco Shared STP multicast (01-00-0C-CC-CC-CD)");
    return true;
  }

  return false;
}

// Helper function to check PROFINET multicast
static inline bool is_profinet_multicast(
    const unsigned char* dest, const void* data_end) {
  if (dest + 5 >= (unsigned char*) data_end) return false;

  if (dest[0] == 0x01 && dest[1] == 0x0e && dest[2] == 0xcf) {
    bpf_debug(
        "Detected PROFINET multicast: %02x:%02x:%02x", dest[0], dest[1],
        dest[2]);
    bpf_debug(
        "PROFINET multicast (cont): %02x:%02x:%02x", dest[3], dest[4], dest[5]);
    return true;
  }
  return false;
}

// Helper function for Ethernet broadcast
static inline bool is_ethernet_broadcast(
    const unsigned char* dest, const void* data_end) {
  if (dest + 5 >= (unsigned char*) data_end) return false;

  if (dest[0] == 0xff && dest[1] == 0xff && dest[2] == 0xff &&
      dest[3] == 0xff && dest[4] == 0xff && dest[5] == 0xff) {
    bpf_debug("Detected Ethernet broadcast (FF-FF-FF-FF-FF-FF)");
    return true;
  }
  return false;
}

// First function: Checks only if the address has multicast bit set
static inline bool is_basic_multicast(
    const struct ethhdr* eth, const void* data_end) {
  // First, validate eth pointer is within bounds
  if ((void*) (eth + 1) > data_end) return false;

  const unsigned char* dest = eth->h_dest;

  // Check that dest points to valid memory
  if (dest + 5 >= (unsigned char*) data_end) return false;

  // Efficient initial check - all multicast addresses have bit 0 of first byte
  // set
  if (!(dest[0] & 0x01)) {
    bpf_debug("Not a multicast: %02x:%02x:%02x", dest[0], dest[1], dest[2]);
    bpf_debug(
        "Not a multicast (cont): %02x:%02x:%02x", dest[3], dest[4], dest[5]);
    return false;
  }

  // Is a multicast by MAC address definition
  return true;
}

// Second function: Performs detailed checks on specific multicast types
static inline bool is_known_multicast_type(
    const struct ethhdr* eth, const void* data_end) {
  if ((void*) (eth + 1) > data_end) return false;

  const unsigned char* dest = eth->h_dest;
  if (dest + 5 >= (unsigned char*) data_end) return false;

  uint16_t ethertype = eth->h_proto;
  bpf_debug("Checking multicast with ethertype: 0x%04x", bpf_ntohs(ethertype));

  // Check each multicast type
  if (is_profinet_multicast(dest, data_end) ||
      is_ieee_802_multicast(dest, data_end, ethertype) ||
      is_ieee_tc9_multicast(dest, data_end, ethertype) ||
      is_ipv4_multicast(dest, data_end, ethertype) ||
      is_ipv6_multicast(dest, data_end, ethertype) ||
      is_iec_multicast(dest, data_end, ethertype) ||
      is_cisco_multicast(dest, data_end)) {
    return true;
  }

  bpf_debug("Unknown multicast: %02x:%02x:%02x", dest[0], dest[1], dest[2]);
  bpf_debug(
      "Unknown multicast (cont): %02x:%02x:%02x", dest[3], dest[4], dest[5]);
  return false;
}

// Main function that combines both checks
static inline bool is_multicast_address(
    const struct ethhdr* eth, const void* data_end) {
  // First check if it's a basic multicast
  if (!is_basic_multicast(eth, data_end)) return false;

  // Then check if it's a known multicast type
  return is_known_multicast_type(eth, data_end);
}

#endif /* BPF_MULTICAST_H */