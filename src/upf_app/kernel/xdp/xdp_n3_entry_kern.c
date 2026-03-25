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
 * Changes:     Boy Scout cleanup — renamed upf_n3_entry.c -> xdp_n3_entry.c.
 *              Replaced inline bounds checks with protocol helpers from
 *              protocols/{eth,ip,udp,gtpu}.h to avoid code duplication.
 *              Applied consistent section separators and updated 3GPP refs.
 *              Updated includes: removed unused pfcp_far/pfcp_pdr;
 *              removed upf_xdp_maps.h (no session maps used at entry point);
 *              xdp_stats_kern.h -> stats_maps.h, xdp_stats_kern_user.h -> stats_types.h.
 * 3GPP Refs:   3GPP TS 29.281 V17.x.x §5.1    — GTP-U header format
 *              3GPP TS 29.281 V17.x.x §5.5.3.3 — PDU Session Container
 *              3GPP TS 29.244 V17.10.0 §8.2.3  — F-TEID IE
 *              3GPP TS 29.244 V17.10.0 §8.2.62 — UE IP Address IE
 *              3GPP TS 29.244 V17.10.0 §8.2.89 — QFI IE
 */
// clang-format on

/**
 * @file  xdp_n3_entry.c
 * @brief XDP entry point for uplink traffic (N3 -> N6) — IP PDU sessions.
 *
 * Handles GTP-U encapsulated packets arriving from the RAN (gNB) on the
 * N3 reference point.  Decapsulates the GTP-U tunnel, extracts the F-TEID,
 * UE IP address, and QFI, then tail-calls the IP session lookup stage.
 *
 * Packet format (input):
 *   [ETH][IP-outer][UDP:2152][GTP-U][PDU Session Container][IP-inner][payload]
 *
 * Fields extracted into packet_context:
 *   pkt_teid — F-TEID from GTP-U header            (§8.2.3)
 *   ue_ip    — inner source IPv4 = UE IP address    (§8.2.62)
 *   qfi      — QFI from PDU Session Container       (§8.2.89)
 *
 * Active pipeline:
 *   [xdp_n3_entry] -> session_lookup_ip -> pdr_match -> Rules apply
 *
 * Entry point: attached to N3 interface via XDP hook.
 * Direction:   RAN -> UPF -> Data Network (uplink).
 */

#define KBUILD_MODNAME xdp_n3_entry

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
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
#include "protocols/gtpu.h"
#include "protocols/eth.h"
#include "protocols/ip.h"
#include "protocols/udp.h"

/* PFCP structures */

/* Pipeline maps and tail-call dispatch */
#include "tail_call_dispatcher.h"

/* Statistics */
#include "stats_maps.h"
#include "stats_types.h"

/* ========================================================================== */
/*                     N3 UPLINK ENTRY POINT (IP PDU)                         */
/* ========================================================================== */

/**
 * @brief N3 uplink entry point — GTP-U decapsulation and session dispatch.
 *
 * Processing sequence:
 *   1. Outer Ethernet  — validate L2, reject non-IPv4
 *   2. Outer IPv4      — validate outer L3
 *   3. Outer UDP       — validate L4, confirm GTP-U port (2152)
 *   4. GTP-U header    — confirm G-PDU, extract F-TEID
 *   5. PDU Session Ctr — extract QFI
 *   6. Inner IPv4      — extract UE source IP
 *   7. Packet context  — populate and tail-call session lookup
 *
 * @param ctx XDP metadata context.
 * @return XDP verdict (via tail call, or fallback on error).
 */
SEC("xdp")
int xdp_n3_entry(struct xdp_md* ctx) {
  bpf_debug("=====< N3 entry: GTP-U uplink (N3 -> N6) >=====");

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
  struct iphdr* ip_outer;

  if (!parse_ipv4(eth, data_end, &ip_outer))
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
  /*  Extract QFI (§8.2.89)                                     */
  /* ---------------------------------------------------------- */
  struct gtpu_extn_pdu_session_container* gtpu_ext;
  u8 qfi;

  void* inner = parse_gtpu_ext_hdr(gtpu, data_end, &gtpu_ext, &qfi);
  if (!inner) return xdp_stats_record_action(ctx, XDP_DROP);

  /* ---------------------------------------------------------- */
  /*  Parse inner IPv4 header                                   */
  /*  Extract UE IP Address (inner source IP, §8.2.62)          */
  /* ---------------------------------------------------------- */
  struct iphdr* ip_inner;
  u32 ue_ip;

  if (!parse_inner_ipv4(inner, data_end, &ip_inner, &ue_ip))
    return xdp_stats_record_action(ctx, XDP_DROP);

  bpf_debug("N3 UL: F-TEID=0x%08x  UE-IP=%pI4  QFI=%u", pkt_teid, &ue_ip, qfi);

  /* ---------------------------------------------------------- */
  /*  Populate packet context                                   */
  /* ---------------------------------------------------------- */
  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("N3: failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  pctx->session_type = SESSION_TYPE_IP_UPLINK;
  pctx->ue_ip        = ue_ip;
  pctx->qfi          = qfi;
  pctx->pkt_teid     = pkt_teid;

  /* ---------------------------------------------------------- */
  /*  Tail call: IP session lookup                              */
  /* ---------------------------------------------------------- */
  TAIL_CALL_NEXT(ctx, PROG_SESSION_LOOKUP_IP);

  /* Tail call should never return — pass to avoid silent drops
   * when the slot is not yet populated in the PROG_ARRAY.     */
  bpf_debug("N3: tail call to PROG_SESSION_LOOKUP_IP failed");
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
