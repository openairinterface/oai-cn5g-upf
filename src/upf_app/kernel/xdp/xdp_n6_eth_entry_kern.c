/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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
#include "utils/mac_resolution.h"

/* Protocol headers (for IP_CSUM_OFFSET and struct definitions) */
#include "protocols/eth.h"
#include "protocols/ip.h"
#include "protocols/gtpu.h"

/* Maps and definitions */
#include "interfaces_maps.h"
#include "eth_pdu_types.h"
#include "eth_pdu_maps.h"

/* IP PDU DL coexistence: tail call dispatch and session metadata */
#include "sdf_types.h"
#include "tail_call_dispatcher.h"

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

  if (dst_ipv4 != 0) {
    /* Resolve next-hop MAC via FIB lookup */
    update_mac_address(ctx, ethh, iph, N3_INTERFACE);
  } else {
    /* Broadcast placeholder (dst_ipv4=0, TEID=0): there is no single
     * destination yet, so a FIB/ARP lookup here can only report a
     * meaningless "hit" against dst 0.0.0.0/whatever default route exists
     */
    bpf_debug(
        "N6 ETH: broadcast placeholder -- MAC left unresolved here, "
        "resolved per-clone by TC fan-out");
  }

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
 * @brief N6 downlink entry point for Ethernet and IP PDU sessions.
 *
 * Four-way dispatch on destination MAC and EtherType:
 *
 *   Case 1  — known MAC:     ETH PDU unicast encap + XDP_REDIRECT to N3.
 *   Case 2  — N6-local:      XDP_PASS to kernel (UPF's own IP or ARP for it).
 *   Case 2b — unknown MAC, IPv4: IP PDU DL; reserve TC metadata and tail-call
 *             PROG_SESSION_LOOKUP_IP (same path as xdp_n6_entry).
 *   Case 3  — unknown MAC, non-IP: ETH PDU broadcast encap (TEID=0) → TC.
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
  /*  Case 2b: IP PDU DL — unknown MAC, IPv4 non-local dest     */
  /*                                                            */
  /*  The destination MAC is not in the Ethernet session table  */
  /*  and the packet is not addressed to the UPF's N6 IP.       */
  /*  If it is an IPv4 frame, the destination IP is a UE address*/
  /*  belonging to an IP PDU session — dispatch to IP session   */
  /*  lookup via tail call (same path as xdp_n6_entry).         */
  /* ---------------------------------------------------------- */
  if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
    /* Reserve XDP metadata for TC QoS shaping (same as n6_entry) */
    if (bpf_xdp_adjust_meta(ctx, -(int) sizeof(struct session_qfi))) {
      bpf_debug("N6 ETH: failed to reserve metadata (IP PDU DL)");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    /* Re-read data/data_end: BPF verifier requires this after adjust_meta */
    data     = (void*) (long) ctx->data;
    data_end = (void*) (long) ctx->data_end;

    struct ethhdr* eth_dl = data;
    if ((void*) (eth_dl + 1) > data_end)
      return xdp_stats_record_action(ctx, XDP_DROP);

    struct iphdr* iph_dl = (struct iphdr*) (eth_dl + 1);
    if ((void*) (iph_dl + 1) > data_end) {
      bpf_debug("N6 ETH: malformed IPv4 header (IP PDU DL)");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    struct packet_context* pctx = GET_PACKET_CONTEXT();
    if (!pctx) {
      bpf_debug("N6 ETH: failed to get packet context (IP PDU DL)");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    u32 ue_ip = bpf_ntohl(iph_dl->daddr);
    bpf_debug("N6 ETH: IP PDU DL: UE-IP=%pI4", &ue_ip);

    pctx->session_type = SESSION_TYPE_IP_DOWNLINK;
    pctx->ue_ip        = ue_ip;
    pctx->pkt_teid     = 0;

    if (!extract_5tuple(
            iph_dl, data_end, &pctx->pkt_filter_src_ip,
            &pctx->pkt_filter_dst_ip, &pctx->pkt_filter_protocol,
            &pctx->pkt_filter_src_port, &pctx->pkt_filter_dst_port)) {
      bpf_debug("N6 ETH: failed to extract 5-tuple (IP PDU DL)");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    TAIL_CALL_NEXT(ctx, PROG_SESSION_LOOKUP_IP);
    bpf_debug("N6 ETH: tail call to PROG_SESSION_LOOKUP_IP failed");
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  /* ---------------------------------------------------------- */
  /*  Case 3: unknown destination MAC (broadcast / flood)       */
  /*                                                            */
  /*  Destination MAC is not in the learning table and not      */
  /*  N6-local and not an IP PDU session packet.                */
  /*  Encapsulate with TEID=0 and XDP_PASS to TC.               */
  /*  The TC program broadcasts to all active ETH PDU sessions. */
  /* ---------------------------------------------------------- */
  bpf_debug("N6 ETH: unknown dest MAC — flooding via TC");

  __u32 ret = create_outer_header_gtpu_ethernet(ctx, 0, 0, 1);

  if (ret != XDP_PASS) return xdp_stats_record_action(ctx, ret);

  /* XDP_PASS delivers to TC for broadcast fan-out */
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
