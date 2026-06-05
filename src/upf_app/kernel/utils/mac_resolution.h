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

    case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
    case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
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

#endif /* MAC_RESOLUTION_H */
