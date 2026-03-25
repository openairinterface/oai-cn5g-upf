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
 * Changes:     Boy Scout cleanup — renamed upf_n3_eth_entry.c -> xdp_n3_eth_entry.c.
 *              Replaced inline ETH/IP/UDP/GTP-U bounds checks with helpers
 *              from protocols/{eth,ip,udp,gtpu}.h to avoid duplication
 *              with xdp_n3_entry.c.
 *              Applied consistent section separators throughout.
 *              Updated includes: removed interfaces.h (not used at ETH UL
 *              entry); removed local redirect_interfaces_map (this program
 *              only tail-calls, never redirects directly);
 *              xdp_stats_kern.h -> stats_maps.h, xdp_stats_kern_user.h -> stats_types.h.
 * 3GPP Refs:   3GPP TS 23.501 §5.6.10.3 — Ethernet PDU Session Type
 *              3GPP TS 29.281 V17.x.x §5.1    — GTP-U header format
 *              3GPP TS 29.281 V17.x.x §5.5.3.3 — PDU Session Container
 */
// clang-format on

/**
 * @file  xdp_n3_eth_entry.c
 * @brief XDP entry point for uplink Ethernet PDU sessions (N3 -> N6).
 *
 * Attached to the N3 interface (RAN-facing) via XDP.  Processes uplink
 * GTP-U packets carrying Ethernet PDU session frames (TS 23.501 §5.6.10.3).
 * The inner payload is a raw Ethernet frame, not IP.
 *
 * Packet structure (uplink):
 *   [ETH-outer][IP-outer][UDP:2152][GTP-U][PDU-Sess-Ctr][ETH-inner][payload]
 *
 * Fields extracted into packet_context:
 *   pkt_teid        — F-TEID from GTP-U header
 *   qfi             — QFI from PDU Session Container
 *   gnb_ipv4        — outer source IP (gNB address, for MAC learning)
 *   inner_eth_src/dst/proto — inner Ethernet frame fields
 *
 * Active pipeline:
 *   [xdp_n3_eth_entry] -> session_lookup_eth -> pdr_match -> Rules Apply
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
 * @brief N3 uplink entry point for Ethernet PDU sessions.
 *
 * Processing sequence:
 *   1. Outer Ethernet  — validate L2, reject non-IPv4
 *   2. Outer IPv4      — validate outer L3
 *   3. Outer UDP       — validate L4, confirm GTP-U port (2152)
 *   4. GTP-U header    — confirm G-PDU, extract F-TEID
 *   5. PDU Session Ctr — extract QFI; returns pointer to inner ETH frame
 *   6. Inner Ethernet  — validate and extract src/dst MAC + EtherType
 *   7. Packet context  — populate and tail-call ETH session lookup
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
  /*  Parse inner Ethernet header                               */
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
  /*  Populate packet context                                   */
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
