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
 *   update_mac_address()            -- FIB-based next-hop MAC resolution
 *                                     with arp_table_map fallback
 *
 * Depends on: interfaces_maps.h, arp_maps.h, utils/logger.h
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
#include "interfaces_maps.h"
#include "arp_maps.h"

/* AF_INET defined directly to avoid pulling in <sys/socket.h>
 * which is a userspace header and not available in BPF compilation. */
#ifndef AF_INET
#define AF_INET 2
#endif

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

/* ==========================================================================
 * update_mac_address -- FIB-based next-hop MAC resolution
 * ========================================================================== */

/**
 * @brief Resolve and write the next-hop MAC addresses via kernel FIB lookup.
 *
 * Primary path: bpf_fib_lookup() resolves the next-hop for the packet's
 * destination IP and writes both src and dst MAC directly into the Ethernet
 * header.
 *
 * Fallback path (FIB miss): looks up the UPF interface IP from
 * upf_interface_map, then resolves the next-hop MAC from arp_table_map.
 * This handles cases where the kernel FIB is not yet populated (e.g. before
 * the first ARP exchange completes).
 *
 * @param ctx       XDP metadata context.
 * @param ethh      Pointer to the Ethernet header to update.
 * @param iph       Pointer to the IPv4 header (source of FIB lookup params).
 * @param direction UPF reference point (N3_INTERFACE / N6_INTERFACE etc.)
 *                  used for the arp_table_map fallback lookup.
 * @return bpf_fib_lookup() return code (BPF_FIB_LKUP_RET_SUCCESS = 0 on hit).
 */
static __always_inline int update_mac_address(
    struct xdp_md* ctx, struct ethhdr* ethh, struct iphdr* iph,
    reference_point_t direction) {
  void* data_end = (void*) (long) ctx->data_end;

  struct bpf_fib_lookup fib_params = {};

  if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
    if ((void*) (iph + 1) > data_end) return -1;

    fib_params.family      = AF_INET;
    fib_params.tos         = iph->tos;
    fib_params.l4_protocol = iph->protocol;
    fib_params.sport       = 0;
    fib_params.dport       = 0;
    fib_params.tot_len     = bpf_ntohs(iph->tot_len);
    fib_params.ipv4_src    = iph->saddr;
    fib_params.ipv4_dst    = iph->daddr;
  }

  fib_params.ifindex = ctx->ingress_ifindex;

  int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

  switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
      bpf_debug("update_mac_address: FIB hit");
      __builtin_memcpy(ethh->h_dest, fib_params.dmac, ETH_ALEN);
      __builtin_memcpy(ethh->h_source, fib_params.smac, ETH_ALEN);
      break;

    case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped
                                         */
    case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be
            dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
    case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress
                                         */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */

    default:
      /* FIB miss -- fall back to UPF ARP table */
      bpf_debug(
          "update_mac_address: FIB miss (rc=%d), trying arp_table_map", rc);

      /* Step 1: resolve interface IP from upf_interface_map */
      reference_point_t nx_key = direction;
      struct interface_config* iface =
          bpf_map_lookup_elem(&upf_interface_map, &nx_key);

      if (!iface) {
        bpf_debug("update_mac_address: interface not in upf_interface_map");
        break;
      }

      /* Step 2: resolve next-hop MAC from arp_table_map */
      struct arp_entry* arp =
          bpf_map_lookup_elem(&arp_table_map, &iface->ipv4_address);

      if (!arp) {
        bpf_debug("update_mac_address: no ARP entry for next-hop");
        break;
      }

      __builtin_memcpy(ethh->h_dest, arp->mac_address, ETH_ALEN);
      bpf_debug("update_mac_address: ARP fallback MAC resolved");
      break;
  }

  return rc;
}

#endif /* BPF_UTILS_H */
