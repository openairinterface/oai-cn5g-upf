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
 * Changes:     Boy Scout cleanup — renamed upf_n6_entry.c -> xdp_n6_entry.c.
 *              Replaced local extract_pkt_filter() with extract_5tuple()
 *              from protocols/ip.h; replaced inline ETH/IP bounds checks
 *              with parse_eth() / parse_ipv4() helpers.
 *              Applied consistent section separators throughout.
 *              Updated includes: removed unused pfcp_far/pfcp_pdr;
 *              upf_xdp_maps.h -> sdf_types.h (only session_qfi needed);
 *              xdp_stats_kern.h -> stats_maps.h, xdp_stats_kern_user.h -> stats_types.h.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §8.2.5  — SDF Filter IE
 *              3GPP TS 29.244 V17.10.0 §8.2.62 — UE IP Address IE
 */
// clang-format on

/**
 * @file  xdp_n6_entry.c
 * @brief XDP entry point for downlink traffic (N6 -> N3) — IP PDU sessions.
 *
 * Handles plain IPv4 packets arriving from the Data Network on the N6
 * reference point. Extracts the UE destination IP and the 5-tuple for
 * SDF filter matching, then tail-calls the IP session lookup stage.
 *
 * Packet format (input):
 *   [ETH][IP][TCP/UDP][payload]
 *
 * Fields extracted into packet_context:
 *   ue_ip                — destination IPv4 = UE IP Address  (§8.2.62)
 *   pkt_filter_{src,dst}_ip, protocol, {src,dst}_port  (§8.2.5)
 *
 * Active pipeline:
 *   [xdp_n6_entry] -> session_lookup_ip -> pdr_match -> Rules Apply
 *
 * Entry point: attached to N6 interface via XDP hook.
 * Direction:   Data Network -> UPF -> RAN (downlink).
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

#include "linux/custom_types.h"
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
