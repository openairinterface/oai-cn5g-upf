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
 * @file upf_n3_eth_entry.c
 * @brief N3 uplink entry point for Ethernet PDU sessions
 *
 * Attached to the N3 interface (RAN-facing) via XDP. Processes uplink
 * GTP-U packets carrying Ethernet PDU session frames (TS 23.501
 * §5.6.10.3). The inner payload is a raw Ethernet frame, not IP.
 *
 * Packet structure (uplink):
 *   [ETH-outer][IP-outer][UDP:2152][GTP-U][PDU-Sess-Ctr][ETH-inner][payload]
 *
 * Chain: [N3_ETH_ENTRY] -> Session Lookup ETH -> PDR Match -> FAR -> ...
 *
 * @see 3GPP TS 23.501 §5.6.10.3 - Ethernet PDU Session Type
 * @see 3GPP TS 29.281 §5.1 - GTP-U Header
 */

#define KBUILD_MODNAME upf_n3_eth_entry

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
#include "protocols/gtpu.h"
#include "interfaces.h"
#include "tail_call_dispatch.h"
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

/* Redirect interfaces map (required by EXECUTE_FINAL_ACTION macro) */
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 10);
  __type(key, __u32);
  __type(value, __u32);
} redirect_interfaces_map SEC(".maps");

/* ========================================================================== */
/*                           N3 ETH ENTRY POINT                               */
/* ========================================================================== */

SEC("xdp")
int upf_n3_eth_entry(struct xdp_md* ctx) {
  bpf_debug("===== ETH PDU UL (TS 23.501 §5.6.10.3) =====");

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  /* ---------------------------------------------------------- */
  /*  Parse outer Ethernet header                               */
  /* ---------------------------------------------------------- */
  struct ethhdr* eth_outer = data;

  if ((void*) (eth_outer + 1) > data_end) {
    bpf_debug("ETH PDU UL: Invalid outer ETH header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  if (eth_outer->h_proto != bpf_htons(ETH_P_IP))
    return xdp_stats_record_action(ctx, XDP_PASS);

  /* ---------------------------------------------------------- */
  /*  Parse outer IPv4 header                                   */
  /* ---------------------------------------------------------- */
  struct iphdr* ip_outer = (void*) (eth_outer + 1);

  if ((void*) (ip_outer + 1) > data_end) {
    bpf_debug("ETH PDU UL: Invalid outer IPv4 header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  if (ip_outer->protocol != IPPROTO_UDP)
    return xdp_stats_record_action(ctx, XDP_PASS);

  /* ---------------------------------------------------------- */
  /*  Parse outer UDP -- check GTP-U port 2152                  */
  /* ---------------------------------------------------------- */
  struct udphdr* udp_outer = (void*) (ip_outer + 1);

  if ((void*) (udp_outer + 1) > data_end) {
    bpf_debug("ETH PDU UL: Invalid outer UDP header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  if (udp_outer->dest != bpf_htons(GTP_UDP_PORT))
    return xdp_stats_record_action(ctx, XDP_PASS);

  bpf_debug("ETH PDU UL: GTP-U traffic detected");

  /* ---------------------------------------------------------- */
  /*  Parse GTP-U header (TS 29.281 §5.1)                      */
  /* ---------------------------------------------------------- */
  struct gtpuhdr* gtpu = (void*) (udp_outer + 1);

  if ((void*) (gtpu + 1) > data_end) {
    bpf_debug("ETH PDU UL: Invalid GTP-U header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  if (gtpu->message_type != GTPU_G_PDU) {
    bpf_debug(
        "ETH PDU UL: msg_type=0x%x (not G-PDU), pass", gtpu->message_type);
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  /* ---------------------------------------------------------- */
  /*  Parse PDU Session Container (TS 29.281 §5.5.3.3)         */
  /* ---------------------------------------------------------- */
  struct gtpu_extn_pdu_session_container* pdu_ctr = (void*) (gtpu + 1);

  if ((void*) (pdu_ctr + 1) > data_end) {
    bpf_debug("ETH PDU UL: Invalid PDU Session Container");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* ---------------------------------------------------------- */
  /*  Extract inner Ethernet header                             */
  /*                                                            */
  /*  Inner ETH offset:                                         */
  /*    outer_ETH + outer_IP + UDP + GTP-U + PDU_Sess_Ctr       */
  /*  = sizeof(ethhdr) + GTP_ENCAPSULATED_SIZE                  */
  /* ---------------------------------------------------------- */
  struct ethhdr* eth_inner =
      (void*) (data + sizeof(struct ethhdr) + GTP_ENCAPSULATED_SIZE);

  if ((void*) (eth_inner + 1) > data_end) {
    bpf_debug("ETH PDU UL: Invalid inner ETH header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  bpf_debug(
      "ETH PDU UL: Inner src=%02x:%02x:%02x", eth_inner->h_source[0],
      eth_inner->h_source[1], eth_inner->h_source[2]);
  bpf_debug(
      "ETH PDU UL: Inner dst=%02x:%02x:%02x", eth_inner->h_dest[0],
      eth_inner->h_dest[1], eth_inner->h_dest[2]);

  /* ---------------------------------------------------------- */
  /*  Populate packet context                                   */
  /* ---------------------------------------------------------- */
  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("ETH PDU UL: Failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  pctx->session_type = SESSION_TYPE_ETH_UPLINK;
  pctx->pkt_teid     = gtpu->teid;
  pctx->qfi          = pdu_ctr->qfi;
  pctx->gnb_ipv4     = ip_outer->saddr; /* Network byte order */

  /* Copy inner ETH MACs for MAC learning + broadcast detect */
  __builtin_memcpy(pctx->inner_eth_src, eth_inner->h_source, ETH_ALEN);
  __builtin_memcpy(pctx->inner_eth_dst, eth_inner->h_dest, ETH_ALEN);
  pctx->inner_eth_proto = eth_inner->h_proto;

  /* Clear IP PDU fields (not used for ETH PDU) */
  pctx->ue_ip               = 0;
  pctx->pkt_filter_src_ip   = 0;
  pctx->pkt_filter_dst_ip   = 0;
  pctx->pkt_filter_src_port = 0;
  pctx->pkt_filter_dst_port = 0;
  pctx->pkt_filter_protocol = 0;

  bpf_debug(
      "ETH PDU UL: TEID=0x%x, QFI=%u, gNB=%pI4", bpf_ntohl(pctx->pkt_teid),
      pctx->qfi, &pctx->gnb_ipv4);

  /* ---------------------------------------------------------- */
  /*  Tail call: ETH Session Lookup                             */
  /* ---------------------------------------------------------- */
  TAIL_CALL_NEXT(ctx, PROG_SESSION_LOOKUP_ETH);

  bpf_debug("ETH PDU UL: Tail call to SESSION_LOOKUP_ETH failed");
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";