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

#include "custom_types.h"
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
 *          (except, for UL, the source one) via
 *          bpf_for_each_map_elem(eth_session_mapping_map).
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
  /* eth_egress_ifindex_map is populated by user-space keyed on FlowDirection
   * (custom_types.h: DOWNLINK=0 -> N3/gNB, UPLINK=1 -> N6/DN). Use those keys,
   * NOT types.h DIR_UPLINK(0)/DIR_DOWNLINK(1) whose numeric values are reversed
   * (that mismatch made the DL egress resolve to N6 and broke UL forwarding).
   */
  int key      = DOWNLINK; /* N3 (gNB-facing) egress */
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
  /*  Inner Ethernet (after the GTP-U extension headers)        */
  /*                                                            */
  /*  Non-G-PDU GTP-U (Echo, Error Indication, ...) is          */
  /*  XDP_PASSed and reaches this hook too: leave it alone.     */
  /* ---------------------------------------------------------- */
  int inner_off = gtpu_inner_offset(data, data_end);
  if (inner_off < 0) {
    bpf_debug("eth_broadcast_tc: not an N3 G-PDU this UPF parses -- skip");
    goto out;
  }
  eth = (struct ethhdr*) ((void*) data + inner_off);
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
  struct callback_ctx cb_ctx = {.skb = skb, .ifindex = *ifindex, .size = 0};

  /* UL detection: packet arrived on the DL egress device (== N3).
   * Use skb->ifindex (the device this TC hook is attached to);
   * skb->ingress_ifindex is unreliable for GTP-U frames here (often 0), which
   * made UL broadcast frames fall into the DL-only path and never get
   * redirected to N6. */
  bpf_debug(
      "eth_broadcast_tc: ifindex=%d ingress_ifindex=%d dl_egress=%d",
      skb->ifindex, skb->ingress_ifindex, *ifindex);
  bool is_uplink = (*ifindex == skb->ifindex);
  if (is_uplink) {
    /* The DL clones reuse the UL container, rewritten in place, so they need
     * it alone and 4 octets. Other layouts (QoS monitoring fields, extra
     * extension headers) still go to N6 below, without clones. */
    if (inner_off != (int) (sizeof(struct ethhdr) + GTP_ENCAPSULATED_SIZE) ||
        gtpuh->next_ext_type != GTP_NEXT_EXT_TYPE) {
      bpf_debug(
          "eth_broadcast_tc: UL extension headers not 4 octets -- N6 only");
      action = TC_ACT_SHOT;
      goto n6;
    }

    /* Skip the source session: pre-seed its SEID in the dedup array. A UL
     * TEID with no session is dropped. */
    __u32 src_teid = bpf_ntohl(gtpuh->teid);
    struct eth_session_id* src =
        bpf_map_lookup_elem(&eth_session_mapping_map, &src_teid);
    if (!src) {
      bpf_debug("eth_broadcast_tc: no session for UL TEID=0x%x", src_teid);
      action = TC_ACT_SHOT;
      goto out;
    }
    cb_ctx.pdu_sessions[0] = (__u32) src->seid;
    cb_ctx.size            = 1;

    /* Clones come from the UPF: its N3 IP is this frame's dst IP. Done in
     * TC, not XDP, as the UDP checksum may be CHECKSUM_PARTIAL. */
    __u32 old_saddr = iph->saddr;
    __u32 new_saddr = iph->daddr;
    iph->saddr      = new_saddr;
    if (bpf_l3_csum_replace(
            skb, IP_CSUM_OFFSET, old_saddr, new_saddr, sizeof(new_saddr)) ||
        bpf_l4_csum_replace(
            skb, UDP_CSUM_OFFSET, old_saddr, new_saddr,
            BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR | sizeof(new_saddr))) {
      bpf_debug("eth_broadcast_tc: UL src IP checksum update failed");
      action = TC_ACT_SHOT;
      goto out;
    }

    /* The clones go DL: turn the UL PDU Session Container into a DL one
     * (TS 38.415 §5.5.2.1: PDU Type 0, no optional fields; octet 2 is
     * PPP | RQI | QFI). broadcast_callback_fn sets each clone's QFI. */
    data     = (void*) (long) skb->data;
    data_end = (void*) (long) skb->data_end;
    struct gtpu_extn_pdu_session_container* ext =
        (struct gtpu_extn_pdu_session_container*) ((void*) data +
                                                   sizeof(struct ethhdr) +
                                                   sizeof(struct iphdr) +
                                                   sizeof(struct udphdr) +
                                                   sizeof(struct gtpuhdr));
    if ((void*) (ext + 1) > data_end ||
        ext->message_length != GTP_EXT_MSG_LEN) {
      bpf_debug("eth_broadcast_tc: unexpected UL PDU Session Container");
      action = TC_ACT_SHOT;
      goto out;
    }
    __u32 old_ext, new_ext;
    __builtin_memcpy(&old_ext, ext, sizeof(old_ext));
    ext->pdu_type = GTP_EXT_PDU_TYPE;
    ext->qfi &= 0x3F;
    cb_ctx.qfi = ext->qfi; /* the frame's QFI, see below */
    __builtin_memcpy(&new_ext, ext, sizeof(new_ext));
    if (bpf_l4_csum_replace(
            skb, UDP_CSUM_OFFSET, old_ext, new_ext,
            BPF_F_MARK_MANGLED_0 | sizeof(new_ext))) {
      bpf_debug("eth_broadcast_tc: UL container checksum update failed");
      action = TC_ACT_SHOT;
      goto out;
    }
  }

  /* Save the frame's QFI for clones of sessions with no known DL QFI: each
   * clone's QFI rewrite changes the skb. UL saved it above. Re-reading data
   * keeps it from being held across the UL block, which would push the
   * debug build past the verifier's 512-byte stack limit. */
  if (!is_uplink) {
    data     = (void*) (long) skb->data;
    data_end = (void*) (long) skb->data_end;
    struct gtpu_extn_pdu_session_container* frame_ext =
        fanout_container(data, data_end);
    cb_ctx.qfi = frame_ext ? frame_ext->qfi : 0;
  }

  bpf_for_each_map_elem(
      &eth_session_mapping_map, broadcast_callback_fn, &cb_ctx, 0);
  action = TC_ACT_SHOT;

  /* size counts visited sessions (UL starts at 1: the source), not clones. */
  if (cb_ctx.size == (is_uplink ? 1 : 0)) {
    bpf_debug(
        "eth_broadcast_tc: %s fan-out found no other session -- "
        "eth_session_mapping_map may be empty or unshared",
        is_uplink ? "UL" : "DL");
  }

  /* ---------------------------------------------------------- */
  /*  UL: also forward the original up to N6 (DN-side)          */
  /* ---------------------------------------------------------- */
n6:
  if (is_uplink) {
    key = UPLINK; /* N6 (DN-facing) egress — redirect UL broadcast to the DN */
    ifindex = bpf_map_lookup_elem(&eth_egress_ifindex_map, &key);
    if (!ifindex) {
      bpf_debug("eth_broadcast_tc: UL ifindex not in eth_egress_ifindex_map");
      goto out;
    }

    int roomlen = inner_off;
    data        = (void*) (long) skb->data;
    data_end    = (void*) (long) skb->data_end;
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
