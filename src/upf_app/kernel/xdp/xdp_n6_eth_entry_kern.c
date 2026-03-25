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
 * Changes:     Boy Scout cleanup — renamed upf_n6_eth_entry.c -> xdp_n6_eth_entry.c.
 *              Added protocol includes (protocols/eth.h, protocols/ip.h)
 *              for consistency; inline parsing in create_outer_header_gtpu_ethernet()
 *              kept as-is (encapsulation path writes headers, helpers are for
 *              parsing/reading only).
 *              Applied consistent section separators to main entry point.
 *              Updated includes: interfaces.h -> interfaces_maps.h (provides
 *              upf_interface_map + redirect_interfaces_map); removed local
 *              map definitions that are now centralized in interfaces_maps.h;
 *              xdp_stats_kern.h -> stats_maps.h, xdp_stats_kern_user.h -> stats_types.h.
 * 3GPP Refs:   3GPP TS 23.501 §5.6.10.3 — Ethernet PDU Session Type
 *              3GPP TS 29.281 V17.x.x §5.1    — GTP-U header format
 *              3GPP TS 29.281 V17.x.x §5.5.3.3 — PDU Session Container
 *              3GPP TS 29.244 V17.10.0 §8.2.56 — Outer Header Creation IE
 */
// clang-format on

/**
 * @file  xdp_n6_eth_entry.c
 * @brief XDP entry point for downlink Ethernet PDU sessions (N6 -> N3).
 *
 * Attached to the N6 interface (Data Network-facing) via XDP.  Processes
 * downlink Ethernet frames destined for UEs with Ethernet PDU sessions
 * (TS 23.501 §5.6.10.3).
 *
 * Unlike IP PDU downlink (which goes through the full PDR/FAR chain),
 * ETH PDU downlink is self-contained:
 *   - No UE IP to match against PDRs.
 *   - Forwarding is determined entirely by the MAC learning table.
 *   - Unknown destination MACs are flooded to all sessions via TC.
 *
 * This program does NOT enter the tail-call chain (no PDR/FAR/QER/URR).
 *
 * Logic:
 *   Case 1 — known destination MAC:
 *             GTP-U encapsulate and XDP_REDIRECT to N3 (unicast).
 *   Case 2 — N6-local traffic (UPF's own IP or ARP for it):
 *             XDP_PASS to kernel stack.
 *   Case 3 — unknown destination MAC:
 *             GTP-U encapsulate with TEID=0, XDP_PASS to TC for flood.
 */

#define KBUILD_MODNAME xdp_n6_eth_entry

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
#include <string.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "linux/custom_types.h"
#include "utils/csum.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"

/* Protocol headers (for IP_CSUM_OFFSET and struct definitions) */
#include "protocols/eth.h"
#include "protocols/ip.h"
#include "protocols/gtpu.h"

/* Maps and definitions */
#include "interfaces_maps.h"
#include "eth_pdu_types.h"
#include "eth_pdu_maps.h"

/* Statistics */
#include "stats_maps.h"
#include "stats_types.h"

/* ========================================================================== */
/*         GTP-U ENCAPSULATION FOR ETHERNET FRAMES (TS 29.281 §5.1)          */
/* ========================================================================== */

/**
 * @brief Prepend a GTP-U tunnel header stack before an Ethernet frame.
 *
 * Builds:
 *   [ETH][IP][UDP:2152][GTP-U][PDU Session Container] + existing ETH frame
 *
 * Used for both unicast (known MAC, real TEID/gNB-IP) and broadcast
 * (TEID=0, dst-IP=0, handed to TC for fan-out).
 *
 * @param ctx      XDP metadata context.
 * @param teid     Downlink GTP-U TEID (network byte order); 0 = broadcast.
 * @param dst_ipv4 Destination gNB IPv4 (network byte order); 0 = broadcast.
 * @param qfi      QoS Flow Identifier for the PDU Session Container.
 * @return XDP_PASS on success; XDP_DROP on headroom / bounds error.
 */
static __always_inline __u32 create_outer_header_gtpu_ethernet(
    struct xdp_md* ctx, __u32 teid, __u32 dst_ipv4, __u32 qfi) {
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;
  int pkt_len    = (int) (data_end - data);

  /* Expand headroom: outer ETH + IP + UDP + GTP-U + PDU Session Ctr */
  int roomlen = (int) (GTP_ENCAPSULATED_SIZE + sizeof(struct ethhdr));

  if (bpf_xdp_adjust_head(ctx, -roomlen)) {
    bpf_debug("N6 ETH: failed to expand headroom for GTP-U encap");
    return XDP_DROP;
  }

  data     = (void*) (long) ctx->data;
  data_end = (void*) (long) ctx->data_end;

  /* Retrieve N3 source IP */
  reference_point_t n3_key = N3_INTERFACE;
  struct interface_config* n3 =
      bpf_map_lookup_elem(&upf_interface_map, &n3_key);

  if (!n3) {
    bpf_debug("N6 ETH: N3 interface not configured");
    return XDP_DROP;
  }

  /* ---------------------------------------------------------- */
  /*  Outer Ethernet header                                     */
  /* ---------------------------------------------------------- */
  struct ethhdr* ethh = data;
  if ((void*) (ethh + 1) > data_end) return XDP_DROP;

  ethh->h_proto = bpf_htons(ETH_P_IP);

  /* ---------------------------------------------------------- */
  /*  Outer IPv4 header                                         */
  /* ---------------------------------------------------------- */
  struct iphdr* iph = (void*) (ethh + 1);
  if ((void*) (iph + 1) > data_end) return XDP_DROP;

  iph->version  = 4;
  iph->ihl      = 5;
  iph->tos      = 0;
  iph->tot_len  = bpf_htons((data_end - data) - sizeof(struct ethhdr));
  iph->id       = 0;
  iph->frag_off = 0x0040; /* DF — don't fragment */
  iph->ttl      = 64;
  iph->protocol = IPPROTO_UDP;
  iph->check    = 0;
  iph->saddr    = n3->ipv4_address;
  iph->daddr    = dst_ipv4;

  /* Resolve next-hop MAC via FIB lookup */
  update_mac_address(ctx, ethh, iph, N3_INTERFACE);

  /* ---------------------------------------------------------- */
  /*  Outer UDP header (GTP-U port 2152)                        */
  /* ---------------------------------------------------------- */
  struct udphdr* udph = (void*) (iph + 1);
  if ((void*) (udph + 1) > data_end) return XDP_DROP;

  udph->source = bpf_htons(GTP_UDP_PORT);
  udph->dest   = bpf_htons(GTP_UDP_PORT);
  udph->len    = bpf_htons(
      pkt_len + sizeof(*udph) + sizeof(struct gtpuhdr) +
      sizeof(struct gtpu_extn_pdu_session_container));
  udph->check = 0;

  /* ---------------------------------------------------------- */
  /*  GTP-U header (TS 29.281 §5.1)                            */
  /* ---------------------------------------------------------- */
  struct gtpuhdr* gtpuh = (void*) (udph + 1);
  if ((void*) (gtpuh + 1) > data_end) return XDP_DROP;

  __u8 flags = GTP_EXT_FLAGS;
  __builtin_memcpy(gtpuh, &flags, sizeof(__u8));
  gtpuh->message_type = GTPU_G_PDU;
  gtpuh->message_length =
      bpf_htons(pkt_len + sizeof(struct gtpu_extn_pdu_session_container) + 4);
  gtpuh->teid          = teid;
  gtpuh->sequence      = GTP_SEQ;
  gtpuh->pdu_number    = GTP_PDU_NUMBER;
  gtpuh->next_ext_type = GTP_NEXT_EXT_TYPE;

  /* ---------------------------------------------------------- */
  /*  PDU Session Container extension (TS 29.281 §5.5.3.3)     */
  /* ---------------------------------------------------------- */
  struct gtpu_extn_pdu_session_container* gtpu_ext = (void*) (gtpuh + 1);
  if ((void*) (gtpu_ext + 1) > data_end) return XDP_DROP;

  gtpu_ext->message_length = GTP_EXT_MSG_LEN;
  gtpu_ext->pdu_type       = GTP_EXT_PDU_TYPE;
  gtpu_ext->qfi            = qfi;
  gtpu_ext->next_ext_type  = GTP_EXT_NEXT_EXT_TYPE;

  /* ---------------------------------------------------------- */
  /*  Compute IPv4 header checksum                              */
  /* ---------------------------------------------------------- */
  __wsum l3sum = pcn_csum_diff(0, 0, (__be32*) iph, sizeof(*iph), 0);
  pcn_l3_csum_replace(ctx, IP_CSUM_OFFSET, 0, l3sum, 0);

  bpf_debug("N6 ETH: GTP-U encap done (TEID = 0x%x)", bpf_ntohl(teid));
  return XDP_PASS;
}

/* ========================================================================== */
/*                        N6 ETH DL ENTRY POINT                               */
/* ========================================================================== */

/**
 * @brief N6 downlink entry point for Ethernet PDU sessions.
 *
 * Three-way dispatch on the destination MAC:
 *
 *   Case 1 — known MAC:  unicast encap + XDP_REDIRECT to N3.
 *   Case 2 — N6-local:   XDP_PASS to kernel (UPF's own IP or ARP for it).
 *   Case 3 — unknown MAC: broadcast encap (TEID=0) + XDP_PASS to TC.
 *
 * @param ctx XDP metadata context.
 * @return XDP verdict.
 */
SEC("xdp")
int xdp_n6_eth_entry(struct xdp_md* ctx) {
  bpf_debug("=====< N6 ETH entry: downlink ETH PDU >=====");

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  /* ---------------------------------------------------------- */
  /*  Parse Ethernet header                                     */
  /* ---------------------------------------------------------- */
  struct ethhdr* eth = data;

  if ((void*) (eth + 1) > data_end) {
    bpf_debug("N6 ETH: malformed Ethernet header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* ---------------------------------------------------------- */
  /*  Case 1: known destination MAC (unicast)                   */
  /*                                                            */
  /*  Destination MAC is in the learning table — we know        */
  /*  exactly which GTP-U tunnel to use for this UE.            */
  /* ---------------------------------------------------------- */
  struct mac_pdu_session_value* pdu_sess =
      bpf_map_lookup_elem(&mac_pdu_session_map, &eth->h_dest);

  if (pdu_sess) {
    bpf_debug("N6 ETH: known MAC -> DL TEID=0x%x", bpf_ntohl(pdu_sess->teid));

    __u32 ret = create_outer_header_gtpu_ethernet(
        ctx, pdu_sess->teid, pdu_sess->ipv4_address, 1);

    if (ret != XDP_PASS) return xdp_stats_record_action(ctx, ret);

    return xdp_stats_record_action(
        ctx, bpf_redirect_map(&redirect_interfaces_map, DOWNLINK, 0));
  }

  /* ---------------------------------------------------------- */
  /*  Case 2: N6-local traffic (destined to the UPF itself)     */
  /*                                                            */
  /*  If the packet is addressed to the UPF's N6 IP or is an   */
  /*  ARP request for it, pass to the kernel stack.             */
  /* ---------------------------------------------------------- */
  reference_point_t n6_key = N6_INTERFACE;
  struct interface_config* n6 =
      bpf_map_lookup_elem(&upf_interface_map, &n6_key);
  __u32 n6_ip = n6 ? n6->ipv4_address : 0;

  if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
    struct iphdr* iph = (struct iphdr*) (eth + 1);

    if ((void*) (iph + 1) > data_end) {
      bpf_debug("N6 ETH: malformed IPv4 header");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    if (iph->daddr == n6_ip) {
      bpf_debug("N6 ETH: N6-local IPv4 — passing to kernel");
      return xdp_stats_record_action(ctx, XDP_PASS);
    }

  } else if (bpf_ntohs(eth->h_proto) == ETH_P_ARP) {
    struct arphdr_ipv4* arp = (struct arphdr_ipv4*) (eth + 1);

    if ((void*) (arp + 1) > data_end) {
      bpf_debug("N6 ETH: malformed ARP packet");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    bpf_debug("N6 ETH: ARP src=%pI4  dst=%pI4", &arp->ar_sip, &arp->ar_tip);

    if (arp->ar_tip == n6_ip) {
      bpf_debug("N6 ETH: N6-local ARP — passing to kernel");
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
  }

  /* ---------------------------------------------------------- */
  /*  Case 3: unknown destination MAC (broadcast / flood)       */
  /*                                                            */
  /*  Destination MAC is not in the learning table and not      */
  /*  N6-local.  Encapsulate with TEID=0 and XDP_PASS to TC.   */
  /*  The TC program broadcasts to all active ETH PDU sessions. */
  /* ---------------------------------------------------------- */
  bpf_debug("N6 ETH: unknown dest MAC — flooding via TC");

  __u32 ret = create_outer_header_gtpu_ethernet(ctx, 0, 0, 1);

  if (ret != XDP_PASS) return xdp_stats_record_action(ctx, ret);

  /* XDP_PASS delivers to TC for broadcast fan-out */
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
