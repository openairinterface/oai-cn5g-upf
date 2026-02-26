#ifndef __PFCP_SESSION_ETH_PDU_H
#define __PFCP_SESSION_ETH_PDU_H

// clang-format off
#include <types.h>
// clang-format on
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <endian.h>
#include <utils/logger.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <protocols/eth.h>
#include <protocols/gtpu.h>
#include <protocols/ip.h>
#include <protocols/udp.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <ie/fteid.h>

#include <utils/multicast.h>

#include <mac_pdu_session_key.h>
#include <pfcp_session_eth__lookup_maps.h>
#include <far_maps.h>

/*----------------------------------------------------------------------------------------------------------------*/
struct arphdr {
  __be16 ar_hrd;        /* format of hardware address	*/
  __be16 ar_pro;        /* format of protocol address	*/
  unsigned char ar_hln; /* length of hardware address	*/
  unsigned char ar_pln; /* length of protocol address	*/
  __be16 ar_op;         /* ARP opcode (command)		*/

  unsigned char ar_sha[ETH_ALEN]; /* sender hardware address	*/
  __be32 ar_sip;                  /* sender IP address		*/
  unsigned char ar_tha[ETH_ALEN]; /* target hardware address	*/
  __be32 ar_tip;                  /* sender IP address		*/
} __attribute__((packed));

static __always_inline u32 create_outer_header_gtpu_ethernet(
    struct xdp_md* ctx, teid_t_ teid, u32 ipv4_address, u32 qfi) {
  // bpf_debug("Create Outer Header GTPU_IPv4");
  // bpf_debug("Original Packet: Data/UDP/IP/ETH");
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;
  int packet_len = (int) (data_end - data);

  // Adjust space to the left.
  int roomlen = GTP_ENCAPSULATED_SIZE + sizeof(struct ethhdr);

  if (bpf_xdp_adjust_head(ctx, (int32_t) -roomlen)) {
    return XDP_DROP;
  }

  data     = (void*) (long) ctx->data;
  data_end = (void*) (long) ctx->data_end;

  // Retrieve the N3 Interface IP address:
  e_reference_point n3_key = N3_INTERFACE;
  u32 n3_ip;
  if (!retrieve_upf_iface_from_map(n3_key, &n3_ip)) {
    bpf_debug("N3 interface is missing in UPF map, Drop the packet");
    return XDP_DROP;
  }

  /*
  |----------------------------------------------------------------|
  |----------------------- Update ETH header ----------------------|
  |----------------------------------------------------------------|
  */
  struct ethhdr* ethh = data;
  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Invalid pointer");
    return XDP_DROP;
  }

  ethh->h_proto = bpf_htons(ETH_P_IP);

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add IP header -----------------------|
  |----------------------------------------------------------------|
  */
  struct iphdr* iph = (void*) (ethh + 1);
  if ((void*) (iph + 1) > data_end) {
    return XDP_DROP;
  }

  iph->version  = 4;
  iph->ihl      = 5;  // No options
  iph->tos      = 0;
  iph->tot_len  = bpf_htons((data_end - data) - sizeof(struct ethhdr));
  iph->id       = 0;       // No fragmentation
  iph->frag_off = 0x0040;  // Don't fragment; Fragment offset = 0
  iph->ttl      = 64;
  iph->protocol = IPPROTO_UDP;
  iph->check    = 0;
  iph->saddr    = n3_ip;
  iph->daddr    = ipv4_address;

  update_mac_address(ctx, ethh, iph, N3_INTERFACE);

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add UDP header ----------------------|
  |----------------------------------------------------------------|
  */
  struct udphdr* udph = (void*) (iph + 1);
  if ((void*) (udph + 1) > data_end) {
    return XDP_DROP;
  }

  udph->source = bpf_htons(GTP_UDP_PORT);
  udph->dest   = bpf_htons(GTP_UDP_PORT);
  // bpf_htons(p_far->forwarding_parameters.outer_header_creation.port_number);
  udph->len = bpf_htons(
      packet_len + sizeof(*udph) + sizeof(struct gtpuhdr) +
      sizeof(struct gtpu_extn_pdu_session_container));
  udph->check = 0;

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add GTP header ----------------------|
  |----------------------------------------------------------------|
  */
  // TODO: remove this
  // // Update destination mac address
  // if (!update_dst_mac_address(n3_ip, ethh)) {
  //   bpf_debug("N3's Next Hop MAC address not found! Drop the packet");
  // }

  struct gtpuhdr* p_gtpuh = (void*) (udph + 1);
  if ((void*) (p_gtpuh + 1) > data_end) {
    return XDP_DROP;
  }

  u8 flags = GTP_EXT_FLAGS;
  __builtin_memcpy(p_gtpuh, &flags, sizeof(u8));
  p_gtpuh->message_type   = GTPU_G_PDU;
  p_gtpuh->message_length = bpf_htons(
      packet_len + sizeof(struct gtpu_extn_pdu_session_container) + 4);
  p_gtpuh->teid          = teid;
  p_gtpuh->sequence      = GTP_SEQ;
  p_gtpuh->pdu_number    = GTP_PDU_NUMBER;
  p_gtpuh->next_ext_type = GTP_NEXT_EXT_TYPE;

  /*
  |----------------------------------------------------------------|
  |-------------------- Add GTP extension header ------------------|
  |----------------------------------------------------------------|
  */
  struct gtpu_extn_pdu_session_container* p_gtpu_ext_h = (void*) (p_gtpuh + 1);
  if ((void*) (p_gtpu_ext_h + 1) > data_end) {
    return XDP_DROP;
  }

  p_gtpu_ext_h->message_length = GTP_EXT_MSG_LEN;
  p_gtpu_ext_h->pdu_type       = GTP_EXT_PDU_TYPE;
  p_gtpu_ext_h->qfi            = qfi;
  p_gtpu_ext_h->next_ext_type  = GTP_EXT_NEXT_EXT_TYPE;

  /*
  |----------------------------------------------------------------|
  |---------------------- Compute L3 CHECKSUM ---------------------|
  |----------------------------------------------------------------|
  */
  __wsum l3sum = pcn_csum_diff(0, 0, (__be32*) iph, sizeof(*iph), 0);
  int ret      = pcn_l3_csum_replace(ctx, IP_CSUM_OFFSET, 0, l3sum, 0);

  if (ret) {
    bpf_debug("Checksum Calculation Error %d\n", ret);
  }

  bpf_debug(
      "Pushes the GTP-Encapsulated Packet: Data/UDP/IP/EXT/GTP/UDP/IP/ETH");
  return XDP_PASS;
}

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline pfcp_pdr_t_* pfcp_session_s_lookup_precedence__uplink(
    u64 seid, u32 packet_teid, u8 packet_qfi) {
  pfcp_pdr_t_(*pdrs)[MAX_PDRS_PER_SESSION] =
      bpf_map_lookup_elem(&m_eth__session_pdrs, &seid);

  if (!pdrs) {
    bpf_debug("No PDRs found for SEID: %llu", seid);
    return NULL;
  }

  /*
   * The pragma unrol will be replace with:
   *
   *      int i;
   *      bpf_for(i, 0, MAX_PDRS_PER_SESSION) {
   *
   * This is supported on newer kernels (v6.3+), Clang >= 17, libbpf >= 1.3 or
   * so, Linux kernel headers >= 6.3
   */

#pragma clang loop unroll(full)
  for (int i = 0; i < MAX_PDRS_PER_SESSION; i++) {
    pfcp_pdr_t_* pdr_high_prec = &(*pdrs)[i];
    pdi_t_ pdi                 = pdr_high_prec->pdi;

    // TODO [ETH-PDU] support filtering by ethernet packet filters

    if ((bpf_htonl(pdi.source_interface.interface_value) ==
         INTERFACE_VALUE_ACCESS)) {
      // After uplink/downlink separation, we can remove the source_interface
      // check

      bpf_debug(
          "( packet_teid,   pdi.fteid.teid    ) : ( %d  , %d )", packet_teid,
          pdi.fteid.teid);
      bpf_debug(
          "( packet_qfi,    pdi.qfi.qfi       ) : ( %u  , %u )", packet_qfi,
          pdi.qfi.qfi);
      if ((packet_teid == pdi.fteid.teid) && (packet_qfi == pdi.qfi.qfi)) {
        return pdr_high_prec;  // Maybe continue here directly is better
      }
    }
  }

  // No match found
  return NULL;
}

/*---------------------------------------------------------------------------------------------------------------*/
// Helper function to prepare packet for TC and pass it
static int prepare_and_pass_to_tc(
    struct xdp_md* ctx, struct iphdr* iph_outer, void* data_end,
    struct eth__session_id* session, const char* packet_type) {
  bpf_debug("ETH PDU: %s packet detected, passing to TC", packet_type);

  // Update the TIED to the DL TIED which will be used by the TC broadcast
  // to know which TIED not to send a request to
  struct udphdr* udph = (struct udphdr*) (iph_outer + 1);
  if ((void*) udph + sizeof(*udph) > data_end) {
    bpf_debug("ETH PDU: Invalid UDP packet");
    return XDP_DROP;
  }

  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("ETH PDU: Invalid UDP packet");
    return XDP_DROP;
  }

  gtpuh->teid = session->teid_dl;

  return XDP_PASS;
}

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline u32 handle_far__uplink(
    struct xdp_md* ctx, teid_t_ teid, u8 qfi, u8 source_value,
    struct ethhdr* eth) {
  bpf_debug("Handling uplink FAR ETH PDU session traffic");
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;
  int action     = XDP_PASS;

  // TODO [ETH-PDU] support other eth pkt filters
  struct eth__session_id* session =
      bpf_map_lookup_elem(&m_eth__session_mapping, &teid);

  if (!session) {
    bpf_debug(
        "ETH DPU: No next prog found for TEID %u, source_value %u, qfi %u",
        teid, source_value, qfi);
    return XDP_DROP;
  }

  u64 seid    = session->seid;
  u32 teid_ul = bpf_htonl(session->teid_ul);
  u32 teid_dl = bpf_htonl(session->teid_dl);
  bpf_debug(
      "Session found ( seid, teid_ul, teid_dl ) : ( %llu, %u, %u )", seid,
      teid_ul, teid_dl);

  // pdu sess info learn mac
  struct iphdr* iph_outer = (void*) (data + sizeof(struct ethhdr));

  if ((void*) iph_outer + sizeof(*iph_outer) > data_end) {
    bpf_debug("ETH PDU: Invalid Outer IP packet");
    return XDP_DROP;
  }

  u32 src_ip_out = iph_outer->saddr;
  struct mac_pdu_session_value pdu_session;
  pdu_session.teid         = session->teid_dl;
  pdu_session.ipv4_address = src_ip_out;
  // TODO [ETH-PDU] use BPF_NOEXIST to avoid multiple write requests
  // For now will update every time an UL packet is received
  // This is to ensure that the latest PDU session info is always available
  bpf_map_update_elem(
      &m_mac_pdu_session, &eth->h_source, &pdu_session, BPF_ANY);

  bpf_debug(
      "Inner Eth: %02x:%02x:%02x", eth->h_dest[0], eth->h_dest[1],
      eth->h_dest[2]);

  struct ethhdr inner_eth_copy = {0};
  // Init inner eth
  __builtin_memcpy(&inner_eth_copy, eth, sizeof(*eth));

  bpf_debug(
      "Inner Eth Copy: %02x:%02x:%02x", inner_eth_copy.h_dest[0],
      inner_eth_copy.h_dest[1], inner_eth_copy.h_dest[2]);

  bpf_debug(
      "ETH PDU: Found next prog, DL teid %u, seid %u", session->teid_dl,
      session->seid);

  // Make a copy of the
  // TODO [ETH-PDU] move this logic inside if (p_far) block after fixing prog
  // not found issue
  if ((void*) (data + sizeof(*eth)) > data_end) {
    return XDP_DROP;
  }

  pfcp_pdr_t_* pdr_high_precedence =
      pfcp_session_s_lookup_precedence__uplink(seid, teid_ul, qfi);

  if (!pdr_high_precedence) {
    bpf_debug(
        "PFCP Session's Lookup (Find matching PDR of the PFCP session with "
        "highest precedence) failed");
    return XDP_PASS;
  }

  u32 pdr_id = pdr_high_precedence->pdr_id.rule_id;
  bpf_debug("Highest precedence PDR found %x", pdr_id);

  /*
    |-----------------------------------------------------------------------|
    |--------------------- Apply Rules in Matching PDR ---------------------|
    |----------------------------- (FARs, QERs) ----------------------------|
    |-----------------------------------------------------------------------|
    */
  struct pdrs_per_session key_rules_matching_pdr = {0};
  key_rules_matching_pdr.pdr_id                  = pdr_id;
  key_rules_matching_pdr.seid                    = seid;

  // TODO [ETH-PDU] support other eth pkt filters
  struct rules_match_pdr* rules = {0};
  rules = bpf_map_lookup_elem(&m_eth__rules_match_pdr, &key_rules_matching_pdr);

  if (!rules) {
    bpf_debug("No rule was found for the PDR");
    return XDP_PASS;
  }

  pfcp_far_t_* p_far = &rules->far;

  if (p_far) {
    // TODO [ETH-PDU] support other destinations and actions on the packet
    // Redirect to data network.

    // Validate eth pointer is within bounds
    if ((void*) (eth + 1) > data_end) {
      bpf_debug("Invalid Ethernet header");
      return XDP_DROP;
    }

    bpf_debug(
        "Checking packet with dest MAC %02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
    bpf_debug(
        "Checking packet with dest MAC (cont) %02x:%02x:%02x", eth->h_dest[3],
        eth->h_dest[4], eth->h_dest[5]);

    // Check if it's a broadcast packet - if so, pass to TC immediately
    if (is_ethernet_broadcast(eth->h_dest, data_end)) {
      return prepare_and_pass_to_tc(
          ctx, iph_outer, data_end, session, "Broadcast");
    }

    // Check if it's any other known multicast address
    if (is_multicast_address(eth, data_end)) {
      return prepare_and_pass_to_tc(
          ctx, iph_outer, data_end, session, "Multicast");
    }

    // If we reach here, it's not a broadcast or multicast packet,
    // so continue with GTP header removal...

    // Remove the GTP header
    bpf_debug("Removing GTP header for TEID %u", teid);

    int roomlen = GTP_ENCAPSULATED_SIZE + sizeof(struct ethhdr);
    if (bpf_xdp_adjust_head(ctx, (int32_t) roomlen)) {
      bpf_debug("Failed to adjust head for GTP encapsulation");
      return XDP_DROP;
    }
    data     = (void*) (long) ctx->data;
    data_end = (void*) (long) ctx->data_end;
    bpf_debug("Adjusted head for GTP encapsulation");

    struct ethhdr* ethh = data;
    if ((void*) (ethh + 1) > data_end) {
      bpf_debug("Invalid pointer after GTP header removal");
      return XDP_DROP;
    }
    bpf_debug(
        "Adjusted head for GTP encapsulation, new ETH header: %02x:%02x:%02x",
        ethh->h_dest[0], ethh->h_dest[1], ethh->h_dest[2]);

    // Copy inner eth
    __builtin_memcpy(ethh, &inner_eth_copy, sizeof(struct ethhdr));

    bpf_debug(
        "-- After Adjusted head for GTP encapsulation, new ETH header: "
        "%02x:%02x:%02x",
        ethh->h_dest[0], ethh->h_dest[1], ethh->h_dest[2]);

    bpf_debug("The Packet is redirected for transmission to DN ...");

    return bpf_redirect_map(&m_redirect_interfaces, UPLINK, 0);

  } else {
    bpf_debug("ETH PDU: No FAR entry found for TEID %u", teid);

    // TODO [ETH-PDU] handle the case when no FAR entry is found

    return XDP_PASS;
  }
}

/**
 * @brief Handle UDP header.
 *
 * @param ctx The user accessible metadata for xdp packet hook.
 * @param udph The UDP header.
 * @return u32 The XDP action.
 */

static __always_inline u32
handle_uplink_traffic__eth_pdu(struct xdp_md* ctx, struct udphdr* udph) {
  bpf_debug("Handling uplink ETH PDU session traffic");
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;
  int action     = XDP_PASS;

  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);

  // Check if the GTP header extends beyond the data end.
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("ETH PDU: Invalid GTPU packet");
    return XDP_DROP;
  }

  if (gtpuh->message_type != GTPU_G_PDU) {
    bpf_debug(
        "Message type 0x%x is not GTPU GPDU(0x%x)\n", gtpuh->message_type,
        GTPU_G_PDU);
    return XDP_PASS;
  }

  struct gtpu_extn_pdu_session_container* pdu_container =
      (struct gtpu_extn_pdu_session_container*) (gtpuh + 1);

  // Check if the PDU session container extends beyond the data end.
  if ((void*) pdu_container + sizeof(*pdu_container) > data_end) {
    bpf_debug("ETH PDU: Invalid PDU session container");
    return XDP_DROP;
  }

  struct ethhdr* eth = data + GTP_ENCAPSULATED_SIZE + sizeof(struct ethhdr);

  if ((void*) eth + sizeof(*eth) > data_end) {
    bpf_debug("ETH PDU: Invalid Ethernet packet");
    return XDP_DROP;
  }

  // action = tail_call_next_prog__eth_pdu(
  //     ctx, gtpuh->teid, INTERFACE_VALUE_ACCESS, eth);

  action = handle_far__uplink(
      ctx, gtpuh->teid, pdu_container->qfi, INTERFACE_VALUE_ACCESS, eth);

  return action;
}

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline u32
handle_downlink_traffic__eth_pdu(struct xdp_md* ctx) {
  bpf_debug("Handling downlink ETH PDU session traffic");
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  struct ethhdr* eth = data;
  if ((void*) eth + sizeof(*eth) > data_end) {
    bpf_debug("ETH PDU: Invalid ETH packet");
    return XDP_DROP;
  }

  struct mac_pdu_session_value* pdu_session =
      bpf_map_lookup_elem(&m_mac_pdu_session, &eth->h_dest);
  if (pdu_session) {
    bpf_debug(
        "ETH PDU: Found PDU session in MAC learning table. DL TEID: %u",
        pdu_session->teid);
    create_outer_header_gtpu_ethernet(
        ctx, pdu_session->teid, pdu_session->ipv4_address, 1);
    return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
  }

  // For IP packet with dest IP equal to N6 interface IP address, we don't
  // need to do anything. Pass it up the network stack.
  e_reference_point n6_key = N6_INTERFACE;
  u32 n6_ip                = 0;
  if (!retrieve_upf_iface_from_map(n6_key, &n6_ip)) {
    bpf_debug("N6 interface is missing in UPF map, Doing nothing");
  }

  if (bpf_htons(eth->h_proto) == ETH_P_IP) {
    struct iphdr* iph = (struct iphdr*) (eth + 1);
    if ((void*) iph + sizeof(*iph) > data_end) {
      bpf_debug("ETH PDU: Invalid IPv4 Packet");
      return XDP_DROP;
    }

    if (iph->daddr == n6_ip) {
      bpf_debug("ETH PDU: This is a N6 traffic");
      return XDP_PASS;
    }
  } else if (bpf_htons(eth->h_proto) == ETH_P_ARP) {
    struct arphdr* arp = (struct arphdr_ipv4*) (eth + 1);
    if ((void*) (arp + 1) > data_end) {
      bpf_debug("ETH PDU: Invalid ARP Packet");
      return XDP_DROP;
    }

    bpf_debug(
        "ETH PDU: ARP packet, src_ip %pi4, dest_ip %pi4", &arp->ar_sip,
        &arp->ar_tip);

    if (arp->ar_tip == n6_ip) {
      bpf_debug("ETH PDU: This is a N6 traffic");
      return XDP_PASS;
    }
  } else if (bpf_htons(eth->h_proto) == 0xC0A8) {
    bpf_debug("ETH PDU: This is a Unknown traffic");
    return XDP_PASS;
  }

  // Print protocol type
  bpf_debug(
      "ETH PDU: No PDU session found, passing to TC to send to all PDU "
      "sessions");
  /* Packet is coming from N6 and dest mac is not in the map, so we need to
   * to forward it to all PDU sessions. We have a single N3 interface, so we
   * can use the same interface for all PDU sessions. Put IP address of the
   * N3 interface in the GTP header. The sending to all PDU sessions is
   * handled by the TC program.
   * */
  create_outer_header_gtpu_ethernet(ctx, 0, 0, 1);
  return XDP_PASS;
}

static __always_inline int entry_point_uplink__eth_pdu(struct xdp_md* ctx) {
  bpf_debug("===== ETH PDU UL =======");
  void* data_end = (void*) (long) ctx->data_end;
  void* data     = (void*) (long) ctx->data;
  int action     = XDP_PASS;

  struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(struct ethhdr));
  if ((void*) (iph + 1) > data_end) {
    bpf_debug("ETH PDU: Invalid IPv4 Packet");
    goto out;
  }

  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr* udph = (struct udphdr*) (iph + 1);

    // Check if the UDP header extends beyond the data end.
    if ((void*) (udph + 1) > data_end) {
      bpf_debug("ETH PDU: Invalid UDP packet");
      action = XDP_DROP;
      goto out;
    }

    if (bpf_htons(udph->dest) == GTP_UDP_PORT) {
      bpf_debug("ETH PDU: This is a GTP traffic");
      action = handle_uplink_traffic__eth_pdu(ctx, udph);
      goto out;
    }
  }

out:
  return action;
}

static __always_inline int entry_point_downlink__eth_pdu(struct xdp_md* ctx) {
  bpf_debug("===== ETH PDU DL =======");
  int action = XDP_PASS;

  action = handle_downlink_traffic__eth_pdu(ctx);

  return action;
}

#endif /* __PFCP_SESSION_ETH_PDU_H */