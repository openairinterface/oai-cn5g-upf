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

/**
 * @file upf_n3_entry.c
 * @brief XDP entry point for uplink traffic (N3→N6) — IP PDU sessions
 *
 * Handles GTP-U encapsulated packets arriving from the RAN (gNB) on the
 * N3 reference point. Parses GTP-U headers, extracts identification
 * fields (F-TEID, UE IP, QFI), and tail-calls the session lookup.
 *
 * Packet format (input):
 *   [ETH][IP-outer][UDP:2152][GTP-U][PDU Session Container][IP-inner][payload]
 *
 * Extracted fields → packet_context:
 *   - pkt_teid: F-TEID from GTP-U header (TS 29.244 §8.2.3)
 *   - ue_ip:    Inner source IP = UE IP Address (TS 29.244 §8.2.36)
 *   - qfi:      QFI from PDU Session Container (TS 29.281 §5.5.3.3)
 *
 * Entry point: Attached to N3 interface via XDP
 * Direction: RAN → UPF → Data Network
 *
 * @see 3GPP TS 29.281 §5.1 - GTP-U header format
 * @see 3GPP TS 29.281 §5.5.3.3 - PDU Session Container
 * @see 3GPP TS 29.244 §8.2.3 - F-TEID IE
 */

#define KBUILD_MODNAME upf_n3_entry

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

/* Protocols */
#include "protocols/gtpu.h"

/* PFCP structures */
#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_pdr.h"

/* Maps and definitions */
#include "upf_xdp_maps.h"
#include "tail_call_dispatch.h"
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

/* ========================================================================== */
/*                     N3 UPLINK ENTRY POINT (IP PDU)                         */
/* ========================================================================== */

/**
 * @brief XDP program for uplink traffic (N3→N6)
 *
 * Handles GTP-U encapsulated packets from RAN:
 * 1. Parse outer ETH → IPv4 → UDP (port 2152) → GTP-U → Extension
 * 2. Verify GTP-U message type is G-PDU (0xFF)
 * 3. Extract F-TEID, QFI, and inner UE IP
 * 4. Populate packet_context and tail-call session lookup
 *
 * Non-GTP traffic (ARP, IPv6, VLAN) is passed to kernel stack.
 *
 * @param ctx XDP context
 * @return XDP action via tail call or XDP_PASS/XDP_DROP on error
 */
SEC("xdp")
int upf_n3_entry(struct xdp_md* ctx) {
  bpf_debug("========< N3 Entry: GTP-U Uplink (N3 --> N6) >========");

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  /* --- Parse outer Ethernet header --- */
  struct ethhdr* eth = data;

  if ((void*) (eth + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  u16 l3_protocol = bpf_htons(eth->h_proto);
  bpf_debug("Debug: l3_protocol:0x%x", l3_protocol);

  /* Only process IPv4-encapsulated GTP-U */
  switch (l3_protocol) {
    case ETH_P_IP:
      break;
    case ETH_P_ARP:
      bpf_debug("N3: ARP packet - passing to kernel");
      return xdp_stats_record_action(ctx, XDP_PASS);
    case ETH_P_IPV6:
      bpf_debug("N3: IPv6 not supported - passing to kernel");
      return xdp_stats_record_action(ctx, XDP_PASS);
    default:
      bpf_debug("N3: Unknown L3 protocol 0x%x", l3_protocol);
      return xdp_stats_record_action(ctx, XDP_PASS);
  }

  /* --- Parse outer IPv4 → UDP --- */
  struct iphdr* ip_outer = (void*) (eth + 1);

  if ((void*) (ip_outer + 1) > data_end) {
    bpf_debug("Error: Invalid IPv4 header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  struct udphdr* udp_outer = (void*) (ip_outer + 1);

  if ((void*) (udp_outer + 1) > data_end) {
    bpf_debug("Error: Invalid UDP header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* Verify GTP-U port (UDP dst = 2152, IANA assigned) */
  if (bpf_htons(udp_outer->dest) != GTP_UDP_PORT) {
    bpf_debug(
        "N3: Non-GTP-U UDP port %u - passing to kernel",
        bpf_htons(udp_outer->dest));
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  /* --- Parse GTP-U header (TS 29.281 §5.1) --- */
  bpf_debug("Identified Uplink GTP-U Traffic");
  struct gtpuhdr* gtpu = (void*) (udp_outer + 1);

  if ((void*) (gtpu + 1) > data_end) {
    bpf_debug("Error: Invalid GTP-U header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* Only process G-PDU messages (type 0xFF) */
  if (gtpu->message_type != GTPU_G_PDU) {
    bpf_debug(
        "N3: GTP-U message type 0x%02x is not G-PDU (0xFF)",
        gtpu->message_type);
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  /* Extract F-TEID from GTP-U header (TS 29.244 §8.2.3) for PDR matching */
  u32 pkt_teid = bpf_htonl(gtpu->teid);

  /* --- Parse PDU Session Container extension (TS 29.281 §5.5.3.3) --- */
  struct gtpu_extn_pdu_session_container* gtpu_ext = (void*) (gtpu + 1);

  if ((void*) (gtpu_ext + 1) > data_end) {
    bpf_debug("Error: Invalid GTPU Extension header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* Extract QFI (QoS Flow Identifier, TS 29.244 §8.2.89) */
  u8 qfi = gtpu_ext->qfi;

  /* --- Parse inner IP (UE payload) --- */
  struct iphdr* ip_inner = (void*) (gtpu_ext + 1);

  if ((void*) (ip_inner + 1) > data_end)
    return xdp_stats_record_action(ctx, XDP_DROP);

  /* UE IP Address is inner source IP for uplink (TS 29.244 §8.2.36) */
  u32 ue_ip = bpf_htonl(ip_inner->saddr);

  bpf_debug(
      "N3 UL: F-TEID = 0x%x, UE-IP = %pI4, QFI = %u", pkt_teid, &ue_ip, qfi);

  /* --- Populate packet context --- */
  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("Error: Failed to allocate packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  pctx->session_type = SESSION_TYPE_IP_UPLINK;
  pctx->ue_ip        = ue_ip;
  pctx->qfi          = qfi;
  pctx->pkt_teid     = pkt_teid;

  /* --- Tail call: Session Lookup (IP PDU) --- */
  TAIL_CALL_NEXT(ctx, PROG_SESSION_LOOKUP_IP);

  bpf_debug("Error: Tail call to PROG_SESSION_LOOKUP_IP failed");
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
