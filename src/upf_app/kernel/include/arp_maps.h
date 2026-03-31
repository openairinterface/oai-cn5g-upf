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
 * Changes:     Boy Scout cleanup — extracted arp_table_map from
 *              upf_xdp_maps.h into this dedicated file, paired with
 *              arp_types.h.  max_entries = 1 is a runtime placeholder.
 */
// clang-format on

/**
 * @file  arp_maps.h
 * @brief BPF map definition for the ARP next-hop cache.
 *
 * Provides:
 *   arp_table_map  -- IPv4 -> MAC address cache for next-hop resolution
 *
 * Depends on: arp_types.h
 *
 * Used by: xdp_far_apply.c (reads MAC before forwarding)
 *          userspace NextHopFinder (writes resolved MAC entries)
 */

#ifndef __ARP_MAPS_H__
#define __ARP_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "arp_types.h"

/* ==========================================================================
 * .rodata — runtime-configurable size constants
 * ========================================================================== */

/**
 * Set by userspace via bpf_map__set_value_size() / skeleton globals
 * before skel->load(). Shared across all programs via .rodata section.
 */

const volatile int MAX_ARP_ENTRIES SEC(".rodata");

/* ==========================================================================
 * arp_table_map
 * ========================================================================== */

/**
 * @brief Next-hop ARP cache.
 *
 * Key:   u32               IPv4 address (network byte order)
 * Value: struct arp_entry  {mac_address, ipv4_address}
 * Size:  MAX_ARP_ENTRIES (set at runtime)
 *
 * Written by userspace (NextHopFinder) via ARP probing.
 * Read by xdp_far_apply.c to resolve the destination MAC address
 * before redirecting a packet to N3 or N6.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_ARP_ENTRIES */
  __type(key, u32);
  __type(value, struct arp_entry);
} arp_table_map SEC(".maps");

#endif /* __ARP_MAPS_H__ */