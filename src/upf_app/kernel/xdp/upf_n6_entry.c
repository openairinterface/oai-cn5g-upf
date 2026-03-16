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
 * @file upf_n6_entry.c
 * @brief XDP entry point for downlink traffic (N6→N3) — IP PDU sessions
 *
 * Handles plain IP packets arriving from the Data Network on the N6
 * reference point. This single program replaces the previous xdp_qos and
 * xdp_downlink by always reserving XDP metadata space (cheap, harmless
 * when QoS is disabled).
 *
 * Packet format (input):
 *   [ETH][IP][TCP/UDP][payload]
 *
 * Extracted fields → packet_context:
 *   - ue_ip:    Destination IP = UE IP Address (TS 29.244 §8.2.36)
 *   - 5-tuple:  SDF filter matching fields (TS 29.244 §8.2.5)
 *
 * Entry point: Attached to N6 interface via XDP
 * Direction: Data Network → UPF → RAN
 *
 * @see 3GPP TS 29.244 §8.2.5 - SDF Filter IE
 * @see 3GPP TS 29.244 §8.2.36 - UE IP Address IE
 */

#define KBUILD_MODNAME upf_n6_entry

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

/* PFCP structures */
#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_pdr.h"

/* Maps and definitions */
#include "upf_xdp_maps.h"
#include "tail_call_dispatch.h"
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

/* ========================================================================== */
/*                        PACKET FILTER EXTRACTION                            */
/* ========================================================================== */

/**
 * @brief Extract 5-tuple from IP packet for SDF filter matching
 *
 * Extracts packet classification information per TS 29.244 §8.2.5
 * (SDF Filter IE):
 * - Source and destination IP addresses
 * - IP protocol number (IANA assigned)
 * - Source and destination ports (for TCP/UDP)
 *
 * For non-TCP/UDP protocols, ports default to 0 (best-effort QoS flow).
 *
 * @param data Pointer to packet data
 * @param data_end Pointer to end of packet data
 * @param ip IPv4 header
 * @param pctx Packet context to populate filter fields
 * @return RET_SUCCESS or RET_FAILURE
 */
static __always_inline int extract_pkt_filter(
    void* data, void* data_end, struct iphdr* ip, struct packet_context* pctx) {
  if (!ip) return RET_FAILURE;

  pctx->pkt_filter_src_ip   = bpf_ntohl(ip->saddr);
  pctx->pkt_filter_dst_ip   = bpf_ntohl(ip->daddr);
  pctx->pkt_filter_protocol = ip->protocol;

  /* Extract L4 ports for TCP/UDP (IANA protocol numbers) */
  switch (ip->protocol) {
    case IPPROTO_TCP: {
      struct tcphdr* tcp = (struct tcphdr*) (ip + 1);

      if ((void*) (tcp + 1) > data_end) return RET_FAILURE;
      pctx->pkt_filter_src_port = bpf_ntohs(tcp->source);
      pctx->pkt_filter_dst_port = bpf_ntohs(tcp->dest);
      break;
    }
    case IPPROTO_UDP: {
      struct udphdr* udp = (struct udphdr*) (ip + 1);

      if ((void*) (udp + 1) > data_end) return RET_FAILURE;
      pctx->pkt_filter_src_port = bpf_ntohs(udp->source);
      pctx->pkt_filter_dst_port = bpf_ntohs(udp->dest);
      break;
    }
    default:
      /*
       * Non-TCP/UDP protocols have no ports — use best-effort
       * QoS flow (default QFI). Per TS 23.501 §5.7.1.
       */
      pctx->pkt_filter_src_port = 0;
      pctx->pkt_filter_dst_port = 0;
      break;
  }

  return RET_SUCCESS;
}

/* ========================================================================== */
/*                     N6 DOWNLINK ENTRY POINT (IP PDU)                       */
/* ========================================================================== */

/**
 * @brief XDP program for downlink traffic (N6→N3)
 *
 * Unified entry point replacing xdp_qos and xdp_downlink. Handles
 * plain IP packets from the Data Network:
 * 1. Reserve XDP metadata space for TC QoS shaping (always, cheap)
 * 2. Parse ETH → IPv4 headers
 * 3. Extract UE IP (destination = UE) and 5-tuple for SDF matching
 * 4. Populate packet_context and tail-call session lookup
 *
 * Non-IPv4 traffic (ARP, IPv6, VLAN) is passed to kernel stack.
 *
 * @param ctx XDP context
 * @return XDP action via tail call or XDP_PASS/XDP_DROP on error
 */
SEC("xdp")
int upf_n6_entry(struct xdp_md* ctx) {
  bpf_debug("========< N6 Entry: IP Downlink (N6 --> N3) >========");

  /*
   * Reserve XDP metadata space for TC QoS shaping.
   * This is always done regardless of QoS state — the cost is
   * negligible (bpf_xdp_adjust_meta only moves a pointer) and
   * it allows a single entry point for both QoS and non-QoS sessions.
   */
  if (bpf_xdp_adjust_meta(ctx, -(int) sizeof(struct session_qfi))) {
    bpf_debug("Error: Failed to reserve XDP metadata for TC");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  /* --- Parse Ethernet header --- */
  struct ethhdr* eth = data;

  if ((void*) (eth + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  u16 l3_protocol = bpf_htons(eth->h_proto);
  bpf_debug("Debug: l3_protocol:0x%x", l3_protocol);

  switch (l3_protocol) {
    case ETH_P_IP:
      break;
    case ETH_P_ARP:
      bpf_debug("N6: ARP packet - passing to kernel");
      return xdp_stats_record_action(ctx, XDP_PASS);
    case ETH_P_IPV6:
      bpf_debug("N6: IPv6 not supported - passing to kernel");
      return xdp_stats_record_action(ctx, XDP_PASS);
    default:
      bpf_debug("N6: Unknown L3 protocol 0x%x", l3_protocol);
      return xdp_stats_record_action(ctx, XDP_PASS);
  }

  /* --- Parse IPv4 header --- */
  struct iphdr* ip = (void*) (eth + 1);

  if ((void*) (ip + 1) > data_end) {
    bpf_debug("Error: Invalid IPv4 header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /*
   * For downlink, UE IP Address is the destination IP
   * (TS 29.244 §8.2.36: UE IP Address in the DL direction)
   */
  u32 ue_ip = bpf_htonl(ip->daddr);

  bpf_debug("N6 DL: UE-IP = %pI4 ", &ue_ip);

  /* --- Populate packet context --- */
  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("Error: Failed to allocate packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  pctx->session_type = SESSION_TYPE_IP_DOWNLINK;
  pctx->ue_ip        = ue_ip;
  pctx->pkt_teid     = 0; /* Not applicable for downlink */

  /*
   * Extract 5-tuple for SDF filter matching (TS 29.244 §8.2.5).
   * Used by PDR match to classify traffic into QoS flows.
   */
  if (extract_pkt_filter(data, data_end, ip, pctx) != RET_SUCCESS) {
    bpf_debug("N6 DL: Failed to extract SDF filter 5-tuple");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* --- Tail call: Session Lookup (IP PDU) --- */
  TAIL_CALL_NEXT(ctx, PROG_SESSION_LOOKUP_IP);

  bpf_debug("Error: Tail call to PROG_SESSION_LOOKUP_IP failed");
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
