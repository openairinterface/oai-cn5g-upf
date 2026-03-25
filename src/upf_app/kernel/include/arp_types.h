/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */
// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Boy Scout cleanup — split arp_table.h into
 *              arp_types.h (plain-C types, this file) and
 *              arp_maps.h (BPF map definitions).
 *              No functional changes to struct content.
 */
// clang-format on

/**
 * @file  arp_types.h
 * @brief ARP cache entry type definition.
 *
 * Contains only plain-C types — no BPF map definitions.
 * The BPF map (arp_table_map) is in arp_maps.h.
 *
 * Used by: xdp_far_apply.c, xdp_n6_eth_entry.c
 */

#ifndef __ARP_TYPES_H__
#define __ARP_TYPES_H__

#include "linux/custom_types.h"

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