/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef MAC_RESOLUTION_H
#define MAC_RESOLUTION_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "utils/logger.h"
#include "interfaces_maps.h"
#include "arp_maps.h"

/* AF_INET defined directly to avoid pulling in <sys/socket.h>
 * which is a userspace header and not available in BPF compilation. */
#ifndef AF_INET
#define AF_INET 2
#endif

/* ========================================================================== */
/*                    FIB LOOKUP SCRATCH (STACK RELIEF)                       */
/* ========================================================================== */

/**
 * @brief Per-CPU scratch slot for resolve_mac_via_fib()'s bpf_fib_lookup().
 *
 * Keeps the 64-byte struct off the stack so bpf_for_each_map_elem()
 * callbacks (e.g. broadcast_callback_fn()) stay within the verifier's
 * 512-byte combined stack limit. Per-CPU, so no locking is needed.
 * Private to each BPF object by design (not shared; skipped by
 * VerifySharedMapIdentity()).
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bpf_fib_lookup);
} fib_lookup_scratch_map SEC(".maps");

/* ========================================================================== */
/*                      MAC RESOLUTION PRIMITIVES                             */
/* ========================================================================== */

/**
 * @brief Look up dst_ip in arp_table_map; on hit, copy its MAC into dst_mac.
 *
 * @param dst_ip  IPv4 address to look up (network byte order).
 * @param dst_mac Output: MAC on hit, untouched on miss.
 * @return true on hit, false on miss.
 */
static __always_inline bool resolve_mac_via_arp(
    __u32 dst_ip, __u8 dst_mac[ETH_ALEN]) {
  struct arp_entry* arp = bpf_map_lookup_elem(&arp_table_map, &dst_ip);
  if (!arp) return false;
  __builtin_memcpy(dst_mac, arp->mac_address, ETH_ALEN);
  return true;
}

/**
 * @brief FIB lookup for dst_ip, writing dmac (and smac if src_mac is
 *        non-NULL) on success. Uses fib_lookup_scratch_map, not the stack.
 *
 * @param ctx         xdp_md* (XDP) or __sk_buff* (TC).
 * @param iph         Bounds-checked IPv4 header supplying saddr, tos,
 *                    protocol and tot_len; NULL leaves them zero.
 * @param dst_ip      Destination IPv4 to resolve (network byte order).
 * @param ifindex     Ingress device, or egress device with
 *                    BPF_FIB_LOOKUP_OUTPUT.
 * @param flags       bpf_fib_lookup() flags (0 or BPF_FIB_LOOKUP_OUTPUT).
 * @param dst_mac     Output: next-hop MAC on success.
 * @param src_mac     Output: egress MAC on success; NULL to skip.
 * @param out_gw_ip   Output: fib->ipv4_dst, written regardless of rc (may
 *                    hold the next-hop gateway IP on a miss); NULL to skip.
 * @return bpf_fib_lookup()'s return code; MACs written only on SUCCESS.
 */
static __always_inline int resolve_mac_via_fib(
    void* ctx, const struct iphdr* iph, __u32 dst_ip, __u32 ifindex,
    __u32 flags, __u8 dst_mac[ETH_ALEN], __u8* src_mac, __u32* out_gw_ip) {
  __u32 scratch_key = 0;
  struct bpf_fib_lookup* fib =
      bpf_map_lookup_elem(&fib_lookup_scratch_map, &scratch_key);
  if (!fib) {
    bpf_debug("resolve_mac_via_fib: fib_lookup_scratch_map lookup failed");
    return -1;
  }
  __builtin_memset(fib, 0, sizeof(*fib));
  fib->family   = AF_INET;
  fib->ipv4_dst = dst_ip;
  fib->ifindex  = ifindex;
  if (iph) {
    fib->tos         = iph->tos;
    fib->l4_protocol = iph->protocol;
    fib->tot_len     = bpf_ntohs(iph->tot_len);
    fib->ipv4_src    = iph->saddr;
  }

  int rc = bpf_fib_lookup(ctx, fib, sizeof(*fib), flags);
  if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
    __builtin_memcpy(dst_mac, fib->dmac, ETH_ALEN);
    if (src_mac) __builtin_memcpy(src_mac, fib->smac, ETH_ALEN);
  }
  if (out_gw_ip) *out_gw_ip = fib->ipv4_dst;
  return rc;
}

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
 * Extracted from utils/bpf_utils.h so that bpf_utils.h does not transitively
 * pull upf_interface_map / arp_table_map into every BPF compile unit. Only
 * programs that actually call update_mac_address() should include this header.
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

  struct iphdr* fib_iph = NULL;
  __u32 dst_ip          = 0;

  if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
    if ((void*) (iph + 1) > data_end) return -1;
    fib_iph = iph;
    dst_ip  = iph->daddr;
  }

  int rc = resolve_mac_via_fib(
      ctx, fib_iph, dst_ip, ctx->ingress_ifindex, 0, ethh->h_dest,
      ethh->h_source, NULL);

  if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
    bpf_debug("update_mac_address: FIB hit");
    return rc;
  }

  /* FIB miss -- fall back to UPF ARP table, keyed by the UPF's own
   * interface IP for `direction` (not the packet's destination). */
  bpf_debug("update_mac_address: FIB miss (rc=%d), trying arp_table_map", rc);

  reference_point_t nx_key = direction;
  struct interface_config* iface =
      bpf_map_lookup_elem(&upf_interface_map, &nx_key);

  if (!iface) {
    bpf_debug("update_mac_address: interface not in upf_interface_map");
    return rc;
  }

  if (resolve_mac_via_arp(iface->ipv4_address, ethh->h_dest)) {
    bpf_debug("update_mac_address: ARP fallback MAC resolved");
  } else {
    bpf_debug("update_mac_address: no ARP entry for next-hop");
  }

  return rc;
}

#endif /* MAC_RESOLUTION_H */
