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
 * Changes:     Boy Scout cleanup — merged bpf_eth_utils.h into this file
 *              (bpf_eth_utils.h had the same include guard BPF_UTILS_H,
 *              causing silent ODR conflicts when both were included).
 *              Removed legacy functions using old map names:
 *                - retrieve_upf_iface_from_map() used m_upf_interfaces ->
 *                  replaced by direct upf_interface_map lookup in callers.
 *                - update_dst_mac_address() used m_arp_table ->
 *                  inlined into update_mac_address() FIB fallback.
 *              Updated update_mac_address() FIB fallback to use:
 *                - upf_interface_map  (was m_upf_interfaces)
 *                - arp_table_map      (was m_arp_table)
 *                - struct interface_config / struct arp_entry
 *                  (were struct s_interface / struct s_arp_mapping)
 *              Removed <sys/socket.h> (invalid in BPF); AF_INET defined
 *              directly to avoid kernel vs userspace header conflicts.
 *              Added OAI license and section separators.
 */
// clang-format on

/**
 * @file  bpf_utils.h
 * @brief BPF utility helpers shared across all XDP/TC programs.
 *
 * Provides:
 *   htons/htonl/ntohs/ntohl macros  -- byte-order conversion guards
 *   swap_src_dst_mac()              -- in-place Ethernet MAC swap
 *
 * Deliberately map-free so it can be safely included from every BPF compile
 * unit. FIB-based next-hop MAC resolution lives in utils/mac_resolution.h.
 *
 * Depends on: utils/logger.h
 */

#ifndef BPF_UTILS_H
#define BPF_UTILS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
#include "utils/logger.h"

/* NOTE: interfaces_maps.h and arp_maps.h are NOT included here on purpose --
 * pulling them in would cause every BPF compile unit that uses bpf_utils.h
 * (for the byte-order macros or swap_src_dst_mac) to materialise private
 * copies of upf_interface_map / arp_table_map / redirect_interfaces_map at
 * load time. Programs that need update_mac_address() include the dedicated
 * header utils/mac_resolution.h instead. */

/* ==========================================================================
 * Byte-order conversion macros
 * ========================================================================== */

/*
 * Guard definitions of htons/htonl/ntohs/ntohl.
 * Without these, the BPF verifier may reject extern references with:
 *   "failed to find BTF for extern"
 */

/* Dictionary
 * htons() - host to network short
 * htonl() - host to network long
 * ntohs() - network to host short
 * ntohl() - network to host long
 * If not defined -> "failed to find BTF for extern"
 */

#ifndef htons
#define htons(x) __constant_htons((x))
#endif

#ifndef htonl
#define htonl(x) __constant_htonl((x))
#endif

#ifndef ntohs
#define ntohs(x) __constant_ntohs((x))
#endif

#ifndef ntohl
#define ntohl(x) __constant_ntohl((x))
#endif

/* ========================================================================== */
/* swap_src_dst_mac -- in-place Ethernet header MAC swap                      */
/* ========================================================================== */

/**
 * @brief Swap source and destination MAC addresses in an Ethernet header.
 *
 * Used when reflecting a packet back out the same interface (e.g. ARP reply).
 * Operates directly on the raw packet data pointer; the caller must ensure
 * at least 12 bytes (2x ETH_ALEN) are valid.
 *
 * @param data Pointer to the start of the Ethernet header.
 */
static __always_inline void swap_src_dst_mac(void* data) {
  unsigned short* p = data;
  unsigned short dst[3];

  dst[0] = p[0];
  dst[1] = p[1];
  dst[2] = p[2];
  p[0]   = p[3];
  p[1]   = p[4];
  p[2]   = p[5];
  p[3]   = dst[0];
  p[4]   = dst[1];
  p[5]   = dst[2];

  bpf_debug("swap_src_dst_mac: done");
}

/* update_mac_address() lives in utils/mac_resolution.h -- include that header
 * directly when you need FIB-based next-hop resolution. */

#endif /* BPF_UTILS_H */
