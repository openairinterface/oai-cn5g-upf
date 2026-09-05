/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#define KBUILD_MODNAME xdp_n6_entry

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "custom_types.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"
#include "utils/types.h"

/* Protocol parsing helpers */
#include "protocols/eth.h"
#include "protocols/ip.h"

/* PFCP structures */

/* SDF types (struct session_qfi for XDP metadata reservation) */
#include "sdf_types.h"
#include "tail_call_dispatcher.h"

/* Statistics */
#include "stats_maps.h"
#include "stats_types.h"

/* ========================================================================== */
/*                           N6 downlink entry point (IP PDU)                 */
/* ========================================================================== */

/**
 * @brief N6 downlink entry point — IP PDU session dispatch.
 *
 * Processing sequence:
 *   1. Reserve XDP metadata space for TC QoS shaping (always, cheap)
 *   2. Outer Ethernet  — validate L2, reject non-IPv4
 *   3. Outer IPv4      — validate L3
 *   4. Extract UE IP (destination IP, §8.2.62)
 *   5. Extract 5-tuple for SDF filter matching (§8.2.5)
 *   6. Packet context  — populate and tail-call session lookup
 *
 * @param ctx XDP metadata context.
 * @return XDP verdict (via tail call, or fallback on error).
 */
SEC("xdp")
int xdp_n6_entry(struct xdp_md* ctx) {
  bpf_debug("=====< N6 entry: IP downlink (N6 -> N3) >=====");

  /* ---------------------------------------------------------- */
  /*  Reserve XDP metadata for TC QoS shaping                  */
  /*                                                            */
  /*  Always done regardless of QoS state — bpf_xdp_adjust_meta */
  /*  only moves a pointer, cost is negligible. Allows a single  */
  /*  entry point for both QoS and non-QoS sessions.            */
  /* ---------------------------------------------------------- */
  if (bpf_xdp_adjust_meta(ctx, -(int) sizeof(struct session_qfi))) {
    bpf_debug("N6: failed to reserve XDP metadata for TC");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  /* ---------------------------------------------------------- */
  /*  Parse outer Ethernet header                               */
  /* ---------------------------------------------------------- */
  struct ethhdr* eth;
  bool pass;

  u16 proto = parse_eth(data, data_end, &eth, &pass);
  if (pass) return xdp_stats_record_action(ctx, XDP_PASS);
  if (proto == 0) return xdp_stats_record_action(ctx, XDP_DROP);

  /* ---------------------------------------------------------- */
  /*  Parse outer IPv4 header                                   */
  /* ---------------------------------------------------------- */
  struct iphdr* ip;

  if (!parse_ipv4(eth, data_end, &ip))
    return xdp_stats_record_action(ctx, XDP_DROP);

  /* ---------------------------------------------------------- */
  /*  Extract UE IP Address (destination IP, §8.2.62)           */
  /* ---------------------------------------------------------- */
  /*
   * For downlink, UE IP Address is the destination IP
   * (TS 29.244 §8.2.36: UE IP Address in the DL direction)
   */
  u32 ue_ip = bpf_ntohl(ip->daddr);

  bpf_debug("N6 DL: UE-IP = %pI4 ", &ue_ip);

  /* ---------------------------------------------------------- */
  /*  Populate packet context                                   */
  /* ---------------------------------------------------------- */
  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("N6: failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  pctx->session_type = SESSION_TYPE_IP_DOWNLINK;
  pctx->ue_ip        = ue_ip;
  pctx->pkt_teid     = 0; /* not applicable for downlink */

  /* ---------------------------------------------------------- */
  /*  Extract 5-tuple for SDF filter matching (§8.2.5)          */
  /* ---------------------------------------------------------- */
  if (!extract_5tuple(
          ip, data_end, &pctx->pkt_filter_src_ip, &pctx->pkt_filter_dst_ip,
          &pctx->pkt_filter_protocol, &pctx->pkt_filter_src_port,
          &pctx->pkt_filter_dst_port)) {
    bpf_debug("N6: failed to extract SDF 5-tuple");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* ---------------------------------------------------------- */
  /*  Tail call: IP session lookup                              */
  /* ---------------------------------------------------------- */
  TAIL_CALL_NEXT(ctx, PROG_SESSION_LOOKUP_IP);

  /* Tail call should never return — pass to avoid silent drops
   * when the slot is not yet populated in the PROG_ARRAY.     */
  bpf_debug("N6: tail call to PROG_SESSION_LOOKUP_IP failed");
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
