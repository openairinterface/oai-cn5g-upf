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
#include "upf_map_limits.h"

/* ==========================================================================
 * arp_table_map
 * ========================================================================== */

/**
 * @brief Next-hop ARP cache.
 *
 * Key:   u32               peer / next-hop IPv4 address (network byte order)
 * Value: struct arp_entry  { peer MAC, peer IP }
 * Size:  MAX_ARP_ENTRIES (set at runtime)
 *
 * **Harmonised convention** (used by both N3 and N6 paths):
 *   the map is keyed by the *peer* IP (the next hop on the wire), NOT by
 *   the UPF's own interface IP. This handles multi-gNB and multi-DN
 *   deployments cleanly -- one entry per peer.
 *
 * Writers (userspace, async after the first packet of a session):
 *   - SessionProgramManager::UpdateArpTableForN3() -> arp_table_map[gNB_IP]
 *   - SessionProgramManager::UpdateArpTableForN6() -> arp_table_map[DN_IP]
 *
 * Readers (kernel hot path, in xdp_far_apply.c):
 *   - gtpu_encap_ipv4 (DL): lookup by FAR.outer_header_creation.ipv4_address
 *                            (= the gNB IP attached to the FAR)
 *   - gtpu_decap_ipv4 (UL): lookup by inner_iph->daddr
 *                            (= the inner packet's destination, which equals
 *                             the next-hop IP for directly-connected DN setups)
 *
 * For multi-hop N6 routing (e.g. UE traffic to 8.8.8.8 via an upstream
 * router) the kernel-side fallback should switch to bpf_fib_lookup() --
 * see utils/mac_resolution.h.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_ARP_ENTRIES */
  __type(key, u32);
  __type(value, struct arp_entry);
} arp_table_map SEC(".maps");

#endif /* __ARP_MAPS_H__ */