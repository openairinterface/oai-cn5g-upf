/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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
