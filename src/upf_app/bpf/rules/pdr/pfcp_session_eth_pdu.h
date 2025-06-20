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

#include <pfcp/pfcp_far.h>

#include <protocols/eth.h>
#include <protocols/gtpu.h>
#include <protocols/ip.h>
#include <protocols/udp.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <ie/fteid.h>

#include <utils/gtpu_parse.h>

#include <mac_pdu_session_key.h>
#include <pfcp_session_lookup_maps.h>

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline u32 handle_far__uplink(
  struct xdp_md* ctx, teid_t_ teid, u8 source_value, struct ethhdr* eth) {
  bpf_debug("Handling uplink FAR ETH PDU session traffic");
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;
  int action     = XDP_PASS;

  // Check for the FAR entry in the map
  struct next_rule_eth_prog_index_key map_key;

  // Check types of maps and the keys that have to be included
  __builtin_memset(&map_key, 0, sizeof(struct next_rule_eth_prog_index_key));
  map_key.teid         = teid;
  map_key.source_value = source_value;
  map_key.ethertype    = 0;  // bpf_ntohs(eth->h_proto);

  // TODO [ETH-PDU] support other eth pkt filters
  struct next_rule_eth_prog_index_value* index_value =
      bpf_map_lookup_elem(&m_next_rule_eth_prog_index, &map_key);

  if (!index_value) {
    bpf_debug("ETH DPU: No next prog found for TEID %u, source_value %u", teid, source_value);
    return XDP_DROP;
  }

  // pdu sess info learn mac
  struct iphdr* iph_outer = (void*) (data + sizeof(struct ethhdr));

  if ((void*) iph_outer + sizeof(*iph_outer) > data_end) {
    bpf_debug("ETH PDU: Invalid Outer IP packet");
    return XDP_DROP;
  }
  
  u32 src_ip_out = iph_outer->saddr;
  struct mac_pdu_session_value pdu_session;
  pdu_session.teid         = index_value->teid_dl;
  pdu_session.ipv4_address = src_ip_out;
  // TODO [ETH-PDU] use BPF_NOEXIST to avoid multiple write requests
  // For now will update every time an UL packet is received
  // This is to ensure that the latest PDU session info is always available
  bpf_map_update_elem(
      &m_mac_pdu_session, &eth->h_source, &pdu_session, BPF_ANY);

  
  bpf_debug(
      "Inner Eth: %02x:%02x:%02x",
      eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);

  struct ethhdr inner_eth_copy = {0};
  // Init inner eth
  __builtin_memcpy(&inner_eth_copy, eth, sizeof(*eth));

  bpf_debug(
      "Inner Eth Copy: %02x:%02x:%02x",
      inner_eth_copy.h_dest[0], inner_eth_copy.h_dest[1], inner_eth_copy.h_dest[2]);

  bpf_debug(
      "ETH PDU: Found next prog, DL teid %u, prog_id %u",
      index_value->teid_dl, index_value->prog_id);

    
  // Make a copy of the 
  // TODO [ETH-PDU] move this logic inside if (p_far) block after fixing prog not found issue
  if ((void*) (data + sizeof(*eth)) > data_end) {
    return XDP_DROP;
  }

  __builtin_memcpy(data, eth, sizeof(*eth));
   // Print the first 3 bytes of data
  struct ethhdr* ethhx = data;
  if ((void*) (ethhx + 1) > data_end) {
    bpf_debug("Invalid pointer after GTP header removal");
    return XDP_DROP;
  }
  bpf_debug(
      "Adjusted head for GTP encapsulation, new ETH header: %02x:%02x:%02x",
      ethhx->h_dest[0], ethhx->h_dest[1], ethhx->h_dest[2]);

  // For now we will reuse the prog_id as the key for the FAR map.

  // TODO [ETH-PDU] support other eth pkt filters
  struct pfcp_far_t_* p_far =
      bpf_map_lookup_elem(&m_far_eth, &index_value->prog_id);

  if (p_far) {

    // bpf_debug(
    //     "Found FAR entry for TEID %u, source_value %u, ethertype %u",
    //     p_far->far_id.far_id, source_value, map_key.ethertype);

    // Check if it is a forward action.
    // u8 dest_interface =
    //     p_far->forwarding_parameters.destination_interface.interface_value;

    // // Check forwarding action
    // if (!p_far->apply_action.forw) {
    //   bpf_debug("ETH PDU: Forward Action Is NOT set");
    //   return XDP_PASS;
    // }

    // if (dest_interface != INTERFACE_VALUE_CORE) {
    //   bpf_debug(
    //       "ETH PDU: Destination interface is not CORE, dropping packet");
    //   return XDP_DROP;
    // }

    // TODO [ETH-PDU] support other destinations and actions on the packet
    // Redirect to data network.
    
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
        "-- After Adjusted head for GTP encapsulation, new ETH header: %02x:%02x:%02x",
        ethh->h_dest[0], ethh->h_dest[1], ethh->h_dest[2]);

    bpf_debug("The Packet is redirected for transmission to DN ...");

    return bpf_redirect_map(&m_redirect_interfaces, UPLINK, 0);

  } else {
    bpf_debug("ETH PDU: No FAR entry found for TEID %u", teid);

    // TODO [ETH-PDU] handle the case when no FAR entry is found

    bpf_debug("Removing GTP header for TEID %u", teid);

    int roomlen = GTP_ENCAPSULATED_SIZE + sizeof(struct ethhdr);
    if (bpf_xdp_adjust_head(ctx, (int32_t) roomlen)) {
      bpf_debug("Failed to adjust head for GTP encapsulation");
      return XDP_DROP;
    }
    data     = (void*) (long) ctx->data;
    data_end = (void*) (long) ctx->data_end;

    // Print first bytes of mac address
    struct ethhdr* ethh = data;
    if ((void*) (ethh + 1) > data_end) {
      bpf_debug("Invalid pointer after GTP header removal");
      return XDP_DROP;
    }
    bpf_debug(
        "Adjusted head for GTP encapsulation, new ETH header: %02x:%02x:%02x",
        ethh->h_dest[0], ethh->h_dest[1], ethh->h_dest[2]);

    __builtin_memcpy(ethh, &inner_eth_copy, sizeof(struct ethhdr));

    bpf_debug(
        "-- After Adjusted head for GTP encapsulation, new ETH header: %02x:%02x:%02x",
        ethh->h_dest[0], ethh->h_dest[1], ethh->h_dest[2]);

    return bpf_redirect_map(&m_redirect_interfaces, UPLINK, 0);
    // return XDP_PASS;
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline u32 tail_call_next_prog__eth_pdu(
    struct xdp_md* ctx, teid_t_ teid, u8 source_value, struct ethhdr* eth) {
  bpf_debug("Tail call to next prog for ETH PDU session");
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  struct next_rule_eth_prog_index_key map_key;

  // Check types of maps and the keys that have to be included
  __builtin_memset(&map_key, 0, sizeof(struct next_rule_eth_prog_index_key));
  map_key.teid         = teid;
  map_key.source_value = source_value;
  map_key.ethertype    = 0;  // bpf_ntohs(eth->h_proto);

  // TODO [ETH-PDU] support other eth pkt filters
  struct next_rule_eth_prog_index_value* index_value =
      bpf_map_lookup_elem(&m_next_rule_eth_prog_index, &map_key);

  if (index_value) {
    // pdu sess info learn mac
    struct iphdr* iph_outer = (void*) (data + sizeof(struct ethhdr));

    if ((void*) iph_outer + sizeof(*iph_outer) > data_end) {
      bpf_debug("ETH PDU: Invalid Outer IP packet");
      return XDP_DROP;
    }

    u32 src_ip_out = iph_outer->saddr;
    struct mac_pdu_session_value pdu_session;
    pdu_session.teid         = index_value->teid_dl;
    pdu_session.ipv4_address = src_ip_out;
    bpf_map_update_elem(
        &m_mac_pdu_session, &eth->h_source, &pdu_session, BPF_NOEXIST);

    bpf_debug(
        "ETH PDU: Found next prog, DL teid %u, prog_id %u",
        index_value->teid_dl, index_value->prog_id);
    bpf_tail_call(ctx, &m_next_rule_prog, index_value->prog_id);
    return XDP_PASS;
  }

  bpf_debug("ETH PDU: No next prog found");

  return XDP_DROP;
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

  struct ethhdr* eth = data + GTP_ENCAPSULATED_SIZE + sizeof(struct ethhdr);

  if ((void*) eth + sizeof(*eth) > data_end) {
    bpf_debug("ETH PDU: Invalid Ethernet packet");
    return XDP_DROP;
  }

  bpf_debug(
      "ETH header: %02x:%02x:%02x",
      eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);

  // action = tail_call_next_prog__eth_pdu(
  //     ctx, gtpuh->teid, INTERFACE_VALUE_ACCESS, eth);
  
  action = handle_far__uplink(
      ctx, gtpuh->teid, INTERFACE_VALUE_ACCESS, eth);

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
    bpf_debug("ETH PDU DL: Pdu session found, tied: %u, ip_address %%pi4", pdu_session->teid, & pdu_session->ipv4_address);
    create_outer_header_gtpu(
        ctx, pdu_session->teid, pdu_session->ipv4_address, 1);
    return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
  }

  /* Packet is coming from N6 and dest mac is not in the map, so we need to
   * to forward it to all PDU sessions. We have a single N3 interface, so we
   * can use the same interface for all PDU sessions. Put IP address of the
   * N3 interface in the GTP header. The sending to all PDU sessions is
   * handled by the TC program.
   * */
  bpf_debug("ETH PDU DL: PDU session not found, going to broadcast to all active PDU sessions");
  create_outer_header_gtpu(ctx, 0, 0, 1);
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