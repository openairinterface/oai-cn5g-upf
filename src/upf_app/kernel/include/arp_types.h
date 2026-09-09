/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __ARP_TYPES_H__
#define __ARP_TYPES_H__

#include "custom_types.h"

/* ==========================================================================
 * ARP cache entry
 * ========================================================================== */

/**
 * @brief Next-hop ARP cache entry stored in arp_table_map.
 *
 * Key in arp_table_map:   u32 IPv4 address (network byte order)
 * Value in arp_table_map: struct arp_entry
 *
 * Populated by userspace (NextHopFinder) via ARP resolution.
 * Used by xdp_far_apply.c to fill the destination MAC address
 * before forwarding a packet.
 */
struct arp_entry {
  u8 mac_address[6]; /**< Next-hop Ethernet MAC address           */
  u32 ipv4_address;  /**< Corresponding IPv4 address (redundant,
                      *   kept for reverse lookups / debugging) */
};

#endif /* __ARP_TYPES_H__ */