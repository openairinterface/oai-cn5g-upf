/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#define KBUILD_MODNAME eth_broadcast_tc_kern

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "linux/custom_types.h"
#include "utils/logger.h"
#include "utils/types.h"
#include "protocols/gtpu.h"
#include "protocols/eth.h"
#include "eth_pdu_maps.h"
#include "eth_pdu_types.h"
#include "eth_broadcast.h"

/* ========================================================================== */
/*                          TC INGRESS — ETH PDU BROADCAST                   */
/* ========================================================================== */

/**
 * @brief Fan-out broadcast / multicast frames across all active ETH PDU
 *        sessions (TS 23.501 §5.8.2.5.3).
 *
 * Attached at TC ingress on **both** N3 (gNB-facing) and N6 (DN-facing)
 * interfaces.
 *
 * Flow:
 *   1. Validate outer ETH + IPv4 + UDP/GTP-U headers.
 *   2. Look up the DL egress ifindex (N3) from eth_egress_ifindex_map.
 *   3. Inspect the *inner* Ethernet header (after the GTP-U stack):
 *        - If it's not broadcast / multicast → TC_ACT_RECLASSIFY so the
 *          next TC program in the chain (typically QoS) can handle it.
 *        - Otherwise: clone the packet to every active ETH PDU session
 *          via bpf_for_each_map_elem(eth_session_mapping_map).
 *   4. For UL packets (skb came in on the DL egress ifindex == N3), also
 *      strip the outer GTP-U/UDP/IP/ETH stack and bpf_redirect() the
 *      original up to N6 so it reaches the data network.
 *
 * @return TC_ACT_OK on validation failure, TC_ACT_RECLASSIFY for non-
 *         broadcast traffic, TC_ACT_SHOT after fan-out (DL), or
 *         bpf_redirect() result (UL).
 */
SEC("tc/ingress")
int handle_broadcast(struct __sk_buff* skb) {
  bpf_debug("=====< ETH broadcast TC ingress >=====");

  void* data            = (void*) (long) skb->data;
  void* data_end        = (void*) (long) skb->data_end;
  struct ethhdr* eth    = data;
  int action            = TC_ACT_OK;
  struct ethhdr eth_cpy = {};

  /* ---------------------------------------------------------- */
  /*  Outer Ethernet                                            */
  /* ---------------------------------------------------------- */
  if ((void*) (eth + 1) > data_end) {
    bpf_debug("eth_broadcast_tc: malformed outer Ethernet");
    goto out;
  }

  /* ---------------------------------------------------------- */
  /*  Outer IPv4                                                */
  /* ---------------------------------------------------------- */
  struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(*eth));
  if ((void*) (iph + 1) > data_end) {
    bpf_debug("eth_broadcast_tc: malformed outer IPv4");
    goto out;
  }

  /* ---------------------------------------------------------- */
  /*  Outer UDP — must be GTP-U                                 */
  /* ---------------------------------------------------------- */
  struct udphdr* udph = (struct udphdr*) (iph + 1);
  if ((void*) (udph + 1) > data_end) {
    bpf_debug("eth_broadcast_tc: malformed outer UDP");
    goto out;
  }

  if (bpf_ntohs(udph->dest) != GTP_UDP_PORT) {
    bpf_debug("eth_broadcast_tc: not a GTP-U packet — skipping");
    goto out;
  }

  /* ---------------------------------------------------------- */
  /*  Resolve DL egress ifindex (N3)                            */
  /* ---------------------------------------------------------- */
  int key      = DIR_DOWNLINK;
  int* ifindex = bpf_map_lookup_elem(&eth_egress_ifindex_map, &key);
  if (!ifindex) {
    bpf_debug("eth_broadcast_tc: DL ifindex not in eth_egress_ifindex_map");
    goto out;
  }

  /* ---------------------------------------------------------- */
  /*  Outer GTP-U                                               */
  /* ---------------------------------------------------------- */
  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("eth_broadcast_tc: malformed outer GTP-U");
    goto out;
  }

  /* ---------------------------------------------------------- */
  /*  Inner Ethernet (immediately after the GTP-U stack)        */
  /* ---------------------------------------------------------- */
  eth =
      (struct
       ethhdr*) ((void*) data + sizeof(struct ethhdr) + GTP_ENCAPSULATED_SIZE);
  if ((void*) (eth + 1) > data_end) {
    bpf_debug("eth_broadcast_tc: malformed inner Ethernet");
    goto out;
  }

  /* ---------------------------------------------------------- */
  /*  Classify inner frame                                      */
  /*                                                            */
  /*  Broadcast fan-out applies to:                             */
  /*    - ARP, AARP                                             */
  /*    - LLDP / Profinet / generic multicast                   */
  /*  Anything else gets RECLASSIFY'd to the next TC program.   */
  /* ---------------------------------------------------------- */
  bool is_eth_broadcast =
      ((eth->h_proto == bpf_htons(ETH_P_ARP)) ||
       (eth->h_proto == bpf_htons(ETH_P_AARP)));

  /* Catch broadcast/multicast destination MACs too. eth_is_bcast_or_mcast
   * tests bit 0 of the first MAC octet (IEEE 802.3) which covers broadcast
   * (FF:FF:FF:FF:FF:FF) and every multicast type (LLDP, Profinet, IPv4
   * multicast, etc.) -- semantically equivalent to the obsolete
   * is_basic_multicast() helper from utils/multicast.h. */
  is_eth_broadcast =
      is_eth_broadcast || eth_is_bcast_or_mcast(eth->h_dest, data_end);

  if (!is_eth_broadcast) {
    bpf_debug("eth_broadcast_tc: not broadcast/multicast — RECLASSIFY");
    return TC_ACT_RECLASSIFY;
  }

  __builtin_memcpy(&eth_cpy, eth, sizeof(struct ethhdr));

  /* ---------------------------------------------------------- */
  /*  Fan-out via bpf_for_each_map_elem                         */
  /* ---------------------------------------------------------- */
  struct callback_ctx cb_ctx = {.skb = skb, .ifindex = ifindex, .size = 0};

  /* UL detection: packet ingressed on the DL egress (== N3) */
  bool is_uplink = (*ifindex == skb->ingress_ifindex);
  if (is_uplink) {
    /* Skip the source PDU session — record its TEID up front */
    cb_ctx.pdu_sessions[0] = gtpuh->teid;
    cb_ctx.size            = 1;
  }

  bpf_for_each_map_elem(
      &eth_session_mapping_map, broadcast_callback_fn, &cb_ctx, 0);
  action = TC_ACT_SHOT;

  /* ---------------------------------------------------------- */
  /*  UL: also forward the original up to N6 (DN-side)          */
  /* ---------------------------------------------------------- */
  if (is_uplink) {
    key     = DIR_UPLINK;
    ifindex = bpf_map_lookup_elem(&eth_egress_ifindex_map, &key);
    if (!ifindex) {
      bpf_debug("eth_broadcast_tc: UL ifindex not in eth_egress_ifindex_map");
      goto out;
    }

    int roomlen = sizeof(struct ethhdr) + GTP_ENCAPSULATED_SIZE;
    if (data + roomlen > data_end) {
      bpf_debug("eth_broadcast_tc: data + roomlen > data_end");
      goto out;
    }

    int ret = bpf_skb_adjust_room(skb, -roomlen, BPF_ADJ_ROOM_MAC, 0);
    if (ret) {
      bpf_debug(
          "eth_broadcast_tc: bpf_skb_adjust_room failed (ret=%d, proto=0x%x)",
          ret, skb->protocol);
      goto out;
    }

    data     = (void*) (long) skb->data;
    data_end = (void*) (long) skb->data_end;
    eth      = data;
    if ((void*) (eth + 1) > data_end) {
      goto out;
    }
    __builtin_memcpy(eth, &eth_cpy, sizeof(struct ethhdr));

    bpf_debug(
        "eth_broadcast_tc: UL fan-out done; redirecting to N6 (ifindex=%d)",
        *ifindex);
    return bpf_redirect(*ifindex, 0);
  }

out:
  bpf_debug("eth_broadcast_tc: exiting with action=%d", action);
  return action;
}

/* ========================================================================== */
/*                          LICENSE DECLARATION                               */
/* ========================================================================== */

char _license[] SEC("license") = "GPL";
