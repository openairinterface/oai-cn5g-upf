/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#define KBUILD_MODNAME xdp_n3_eth_entry

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "linux/custom_types.h"
#include "utils/logger.h"

/* Protocol parsing helpers */
#include "protocols/eth.h"
#include "protocols/ip.h"
#include "protocols/udp.h"
#include "protocols/gtpu.h"

/* Maps and dispatch */
#include "tail_call_dispatcher.h"

/* Statistics */
#include "stats_maps.h"
#include "stats_types.h"

/* ========================================================================== */
/*                           N3 ETH ENTRY POINT                               */
/* ========================================================================== */

/**
 * @brief N3 uplink entry point for both IP and Ethernet PDU sessions.
 *
 * Processing sequence:
 *   1. Outer Ethernet  — validate L2, reject non-IPv4
 *   2. Outer IPv4      — validate outer L3
 *   3. Outer UDP       — validate L4, confirm GTP-U port (2152)
 *   4. GTP-U header    — confirm G-PDU, extract F-TEID
 *   5. PDU Session Ctr — extract QFI; returns pointer to inner payload
 *   6. PDU type detect — inspect version nibble of inner byte:
 *        0x4/0x6 → IP PDU  → tail-call PROG_SESSION_LOOKUP_IP
 *        else    → ETH PDU → validate inner ETH + tail-call
 * PROG_SESSION_LOOKUP_ETH
 *
 * @param ctx XDP metadata context.
 * @return XDP verdict (via tail call, or fallback on error).
 */
SEC("xdp")
int xdp_n3_eth_entry(struct xdp_md* ctx) {
  bpf_debug("=====< N3 ETH entry: GTP-U uplink ETH PDU >=====");

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  /* ---------------------------------------------------------- */
  /*  Parse outer Ethernet header                               */
  /* ---------------------------------------------------------- */
  struct ethhdr* eth_outer;
  bool pass;

  u16 proto = parse_eth(data, data_end, &eth_outer, &pass);
  if (pass) return xdp_stats_record_action(ctx, XDP_PASS);
  if (proto == 0) return xdp_stats_record_action(ctx, XDP_DROP);

  /* ---------------------------------------------------------- */
  /*  Parse outer IPv4 header                                   */
  /* ---------------------------------------------------------- */
  struct iphdr* ip_outer;

  if (!parse_ipv4(eth_outer, data_end, &ip_outer))
    return xdp_stats_record_action(ctx, XDP_DROP);

  /* ---------------------------------------------------------- */
  /*  Parse outer UDP -- check GTP-U port 2152                  */
  /* ---------------------------------------------------------- */
  struct udphdr* udp_outer;

  if (!parse_udp_gtpu(ip_outer, data_end, &udp_outer, &pass)) {
    if (pass) return xdp_stats_record_action(ctx, XDP_PASS);
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* ---------------------------------------------------------- */
  /*  Parse GTP-U header (TS 29.281 §5.1)                      */
  /*  Verify G-PDU message type (0xFF), extract F-TEID          */
  /* ---------------------------------------------------------- */
  struct gtpuhdr* gtpu;
  u32 pkt_teid;

  if (!parse_gtpu_hdr(udp_outer, data_end, &gtpu, &pkt_teid, &pass)) {
    if (pass) return xdp_stats_record_action(ctx, XDP_PASS);
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* ---------------------------------------------------------- */
  /*  Parse PDU Session Container (TS 29.281 §5.5.3.3)         */
  /*  Extract QFI; returns pointer to inner Ethernet frame      */
  /* ---------------------------------------------------------- */
  struct gtpu_extn_pdu_session_container* gtpu_ext;
  u8 qfi;

  void* inner = parse_gtpu_ext_hdr(gtpu, data_end, &gtpu_ext, &qfi);
  if (!inner) return xdp_stats_record_action(ctx, XDP_DROP);

  /* ---------------------------------------------------------- */
  /*  Detect inner PDU type: IP or Ethernet                     */
  /*                                                            */
  /*  Inspect the version nibble of the first byte after the   */
  /*  GTP-U extension header:                                   */
  /*    0x4x → IPv4 inner packet  (IP PDU session, TS 23.501)  */
  /*    0x6x → IPv6 inner packet  (IP PDU session, TS 23.501)  */
  /*    else  → Ethernet frame    (ETH PDU session, TS 23.501) */
  /* ---------------------------------------------------------- */
  const u8* inner_byte = (const u8*) inner;
  if ((void*) (inner_byte + 1) > data_end)
    return xdp_stats_record_action(ctx, XDP_DROP);

  u8 inner_version = (*inner_byte) >> 4;

  if (inner_version == 4 || inner_version == 6) {
    /* -------------------------------------------------------- */
    /*  IP PDU session — parse inner IPv4, dispatch to IP lookup*/
    /* -------------------------------------------------------- */
    struct iphdr* ip_inner;
    u32 ue_ip;

    if (!parse_inner_ipv4(inner, data_end, &ip_inner, &ue_ip))
      return xdp_stats_record_action(ctx, XDP_DROP);

    struct packet_context* pctx = GET_PACKET_CONTEXT();
    if (!pctx) {
      bpf_debug("N3 ETH: failed to get packet context (IP PDU)");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    pctx->session_type    = SESSION_TYPE_IP_UPLINK;
    pctx->ue_ip           = ue_ip; /* host byte order */
    pctx->qfi             = qfi;
    pctx->pkt_teid        = pkt_teid; /* host byte order, matches n3_entry */
    pctx->gnb_ipv4        = ip_outer->saddr;
    pctx->inner_eth_proto = 0;
    __builtin_memset(pctx->inner_eth_src, 0, ETH_ALEN);
    __builtin_memset(pctx->inner_eth_dst, 0, ETH_ALEN);

    bpf_debug("N3 ETH: IP PDU UL: UE-IP=%pI4  TEID=0x%x", &ue_ip, pkt_teid);

    TAIL_CALL_NEXT(ctx, PROG_SESSION_LOOKUP_IP);
    bpf_debug("N3 ETH: tail call to PROG_SESSION_LOOKUP_IP failed");
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  /* ---------------------------------------------------------- */
  /*  Ethernet PDU session — parse inner ETH frame              */
  /*                                                            */
  /*  The inner frame starts immediately after the PDU Session  */
  /*  Container. Validate bounds and extract src/dst MACs and   */
  /*  EtherType for MAC learning and broadcast detection.       */
  /* ---------------------------------------------------------- */
  struct ethhdr* eth_inner = inner;

  if ((void*) (eth_inner + 1) > data_end) {
    bpf_debug("N3 ETH: malformed inner Ethernet header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  bpf_debug(
      "N3 ETH: Inner src = %02x:%02x:%02x", eth_inner->h_source[0],
      eth_inner->h_source[1], eth_inner->h_source[2]);
  bpf_debug(
      "N3 ETH: Inner dst = %02x:%02x:%02x", eth_inner->h_dest[0],
      eth_inner->h_dest[1], eth_inner->h_dest[2]);

  /* ---------------------------------------------------------- */
  /*  Populate packet context (ETH PDU)                         */
  /* ---------------------------------------------------------- */
  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("N3 ETH: failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  pctx->session_type = SESSION_TYPE_ETH_UPLINK;
  pctx->pkt_teid     = gtpu->teid; /* network byte order — kept as-is */
  pctx->qfi          = qfi;
  pctx->gnb_ipv4     = ip_outer->saddr; /* network byte order */

  /* Inner ETH fields used for MAC learning and broadcast detection */
  __builtin_memcpy(pctx->inner_eth_src, eth_inner->h_source, ETH_ALEN);
  __builtin_memcpy(pctx->inner_eth_dst, eth_inner->h_dest, ETH_ALEN);
  pctx->inner_eth_proto = eth_inner->h_proto;

  /* Clear IP PDU fields — not applicable for ETH PDU sessions */
  pctx->ue_ip               = 0;
  pctx->pkt_filter_src_ip   = 0;
  pctx->pkt_filter_dst_ip   = 0;
  pctx->pkt_filter_src_port = 0;
  pctx->pkt_filter_dst_port = 0;
  pctx->pkt_filter_protocol = 0;

  bpf_debug(
      "N3 ETH: TEID = 0x%x, QFI = %u, gNB = %pI4", bpf_ntohl(pctx->pkt_teid),
      pctx->qfi, &pctx->gnb_ipv4);

  /* ---------------------------------------------------------- */
  /*  Tail call: ETH session lookup                             */
  /* ---------------------------------------------------------- */
  TAIL_CALL_NEXT(ctx, PROG_SESSION_LOOKUP_ETH);

  /* Tail call should never return — pass to avoid silent drops. */
  bpf_debug("N3 ETH: tail call to PROG_SESSION_LOOKUP_ETH failed");
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
