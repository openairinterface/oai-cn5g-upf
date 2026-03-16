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
 * @file upf_n6_eth_entry.c
 * @brief N6 downlink entry point for Ethernet PDU sessions
 *
 * Attached to the N6 interface (Data Network-facing) via XDP. Processes
 * downlink Ethernet frames that need to be delivered to UEs with
 * Ethernet PDU sessions (TS 23.501 §5.6.10.3).
 *
 * Unlike IP PDU DL (which goes through the full PDR/FAR chain), ETH PDU
 * DL is self-contained because:
 *   - No UE IP to match against PDRs
 *   - Forwarding is determined entirely by MAC learning table
 *   - Unknown dest MACs are flooded to all sessions via TC
 *
 * Logic:
 *   1. Look up destination MAC in mac_pdu_session_map (learning table)
 *   2. If found: GTP-U encapsulate and redirect to N3 (unicast)
 *   3. If not found:
 *      a. Check if dest is N6-local (UPF's own IP or ARP for it)
 *      b. If local: pass to kernel stack
 *      c. If not local: GTP-U encapsulate with teid=0 and XDP_PASS
 *         to TC, which broadcasts to all PDU sessions
 *
 * This program does NOT enter the tail call chain (no PDR/FAR/QER/URR).
 *
 * @see 3GPP TS 23.501 §5.6.10.3 - Ethernet PDU Session Type
 * @see 3GPP TS 29.244 §8.2.56 - Outer Header Creation
 */

#define KBUILD_MODNAME upf_n6_eth_entry

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

/* Protocols */
#include "protocols/gtpu.h"

/* Maps and definitions */
#include "interfaces.h"
#include "eth_pdu_maps.h"
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

/* ========================================================================== */
/*                          REDIRECT INTERFACES MAP                           */
/* ========================================================================== */

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 10);
  __type(key, __u32);
  __type(value, __u32);
} redirect_interfaces_map SEC(".maps");

/* ========================================================================== */
/*                      UPF INTERFACE MAP (for N6/N3 IPs)                     */
/* ========================================================================== */

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 12);
  __type(key, reference_point_t);
  __type(value, struct interface_config);
} upf_interface_map SEC(".maps");

/* ========================================================================== */
/*         GTP-U ENCAPSULATION FOR ETHERNET FRAMES (TS 29.281 §5.1)          */
/* ========================================================================== */

/**
 * @brief Create GTP-U outer headers around an Ethernet frame
 *
 * Prepends [ETH][IP][UDP][GTP-U][PDU-Sess-Container] before the
 * existing Ethernet frame. The inner frame is preserved intact.
 *
 * Used for both unicast (known MAC) and broadcast (teid=0, ip=0)
 * encapsulation.
 *
 * @param ctx      XDP context
 * @param teid     DL TEID (network byte order), 0 for broadcast
 * @param dst_ipv4 gNB IPv4 (network byte order), 0 for broadcast
 * @param qfi      QoS Flow Identifier
 * @return XDP action (XDP_PASS on success, XDP_DROP on failure)
 */
static __always_inline __u32 create_outer_header_gtpu_ethernet(
    struct xdp_md* ctx, teid_t_ teid, __u32 dst_ipv4, __u32 qfi) {
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;
  int packet_len = (int) (data_end - data);

  /* Expand headroom for GTP-U + outer ETH */
  int roomlen = GTP_ENCAPSULATED_SIZE + sizeof(struct ethhdr);

  if (bpf_xdp_adjust_head(ctx, (int32_t) -roomlen)) {
    bpf_debug("ETH PDU DL: Failed to adjust head for GTP encap");
    return XDP_DROP;
  }

  data     = (void*) (long) ctx->data;
  data_end = (void*) (long) ctx->data_end;

  /* Retrieve N3 interface IP address */
  reference_point_t n3_key = N3_INTERFACE;
  struct interface_config* n3_iface =
      bpf_map_lookup_elem(&upf_interface_map, &n3_key);

  if (!n3_iface) {
    bpf_debug("ETH PDU DL: N3 interface not configured");
    return XDP_DROP;
  }

  __u32 n3_ip = n3_iface->ipv4_address;

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
  iph->frag_off = 0x0040; /* Don't fragment */
  iph->ttl      = 64;
  iph->protocol = IPPROTO_UDP;
  iph->check    = 0;
  iph->saddr    = n3_ip;
  iph->daddr    = dst_ipv4;

  /* Update MAC addresses via FIB lookup (TS 29.281 §5.1) */
  update_mac_address(ctx, ethh, iph, N3_INTERFACE);

  /* ---------------------------------------------------------- */
  /*  Outer UDP header (GTP-U port 2152)                        */
  /* ---------------------------------------------------------- */
  struct udphdr* udph = (void*) (iph + 1);

  if ((void*) (udph + 1) > data_end) return XDP_DROP;

  udph->source = bpf_htons(GTP_UDP_PORT);
  udph->dest   = bpf_htons(GTP_UDP_PORT);
  udph->len    = bpf_htons(
      packet_len + sizeof(*udph) + sizeof(struct gtpuhdr) +
      sizeof(struct gtpu_extn_pdu_session_container));
  udph->check = 0;

  /* ---------------------------------------------------------- */
  /*  GTP-U header (TS 29.281 §5.1)                            */
  /* ---------------------------------------------------------- */
  struct gtpuhdr* gtpuh = (void*) (udph + 1);

  if ((void*) (gtpuh + 1) > data_end) return XDP_DROP;

  __u8 flags = GTP_EXT_FLAGS;

  __builtin_memcpy(gtpuh, &flags, sizeof(__u8));
  gtpuh->message_type   = GTPU_G_PDU;
  gtpuh->message_length = bpf_htons(
      packet_len + sizeof(struct gtpu_extn_pdu_session_container) + 4);
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

  bpf_debug(
      "ETH PDU DL: GTP-U encap complete "
      "(TEID=0x%x, TS 29.281 §5.1)",
      bpf_ntohl(teid));
  return XDP_PASS;
}

/* ========================================================================== */
/*                        N6 ETH DL ENTRY POINT                               */
/* ========================================================================== */

SEC("xdp")
int upf_n6_eth_entry(struct xdp_md* ctx) {
  bpf_debug("===== ETH PDU DL (TS 23.501 §5.6.10.3) =====");

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  struct ethhdr* eth = data;

  if ((void*) (eth + 1) > data_end) {
    bpf_debug("ETH PDU DL: Invalid ETH header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* ---------------------------------------------------------- */
  /*  Case 1: Known destination MAC (unicast to specific UE)    */
  /*                                                            */
  /*  Look up dest MAC in MAC learning table. If found, we      */
  /*  know exactly which GTP-U tunnel to use.                   */
  /* ---------------------------------------------------------- */
  struct mac_pdu_session_value* pdu_session =
      bpf_map_lookup_elem(&mac_pdu_session_map, &eth->h_dest);

  if (pdu_session) {
    bpf_debug(
        "ETH PDU DL: MAC found, DL TEID=0x%x", bpf_ntohl(pdu_session->teid));

    __u32 ret = create_outer_header_gtpu_ethernet(
        ctx, pdu_session->teid, pdu_session->ipv4_address, 1);

    if (ret != XDP_PASS) return xdp_stats_record_action(ctx, ret);

    return xdp_stats_record_action(
        ctx, bpf_redirect_map(&redirect_interfaces_map, DOWNLINK, 0));
  }

  /* ---------------------------------------------------------- */
  /*  Case 2: N6-local traffic (destined to UPF itself)         */
  /*                                                            */
  /*  If the packet is addressed to the UPF's N6 IP (or ARP    */
  /*  for it), pass to kernel stack -- no GTP encapsulation.    */
  /* ---------------------------------------------------------- */
  reference_point_t n6_key = N6_INTERFACE;
  struct interface_config* n6_iface =
      bpf_map_lookup_elem(&upf_interface_map, &n6_key);
  __u32 n6_ip = n6_iface ? n6_iface->ipv4_address : 0;

  if (bpf_htons(eth->h_proto) == ETH_P_IP) {
    struct iphdr* iph = (struct iphdr*) (eth + 1);

    if ((void*) (iph + 1) > data_end) {
      bpf_debug("ETH PDU DL: Invalid IPv4 packet");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    if (iph->daddr == n6_ip) {
      bpf_debug("ETH PDU DL: N6-local IPv4 traffic, pass");
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
  } else if (bpf_htons(eth->h_proto) == ETH_P_ARP) {
    struct arphdr_ipv4* arp = (struct arphdr_ipv4*) (eth + 1);

    if ((void*) (arp + 1) > data_end) {
      bpf_debug("ETH PDU DL: Invalid ARP packet");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    bpf_debug("ETH PDU DL: ARP src=%pI4, dst=%pI4", &arp->ar_sip, &arp->ar_tip);

    if (arp->ar_tip == n6_ip) {
      bpf_debug("ETH PDU DL: N6-local ARP, pass");
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
  }

  /* ---------------------------------------------------------- */
  /*  Case 3: Unknown destination MAC (broadcast/flood)         */
  /*                                                            */
  /*  Dest MAC not in learning table and not N6-local.          */
  /*  Encapsulate with teid=0, ipv4=0 and XDP_PASS to TC.      */
  /*  The TC program will broadcast to all ETH PDU sessions.    */
  /* ---------------------------------------------------------- */
  bpf_debug("ETH PDU DL: Unknown dest MAC, flooding via TC");

  __u32 ret = create_outer_header_gtpu_ethernet(ctx, 0, 0, 1);

  if (ret != XDP_PASS) return xdp_stats_record_action(ctx, ret);

  /* XDP_PASS delivers to TC for broadcast fan-out */
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";