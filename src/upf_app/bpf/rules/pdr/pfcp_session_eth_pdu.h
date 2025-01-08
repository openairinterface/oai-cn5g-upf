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

#include <utils/gtpu_parse.h>

#include <mac_pdu_session_key.h>
#include <pfcp_session_lookup_maps.h>
#include <far_maps.h>

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline u32 tail_call_next_prog__eth_pdu(
    struct xdp_md* ctx, teid_t_ teid, u8 source_value, struct ethhdr* eth) {
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  // If inner packet is Ethernet broadcast (ff:ff:ff:ff:ff:ff) pass packet to TC
  if (eth->h_dest[0] == 0xff && eth->h_dest[1] == 0xff &&
      eth->h_dest[2] == 0xff && eth->h_dest[3] == 0xff &&
      eth->h_dest[4] == 0xff && eth->h_dest[5] == 0xff) {
      bpf_printk("Ethernet broadcast detected!\n");
      return XDP_PASS;
  }

  struct next_rule_eth_prog_index_key map_key;

  // Check types of maps and the keys that have to be included
  __builtin_memset(&map_key, 0, sizeof(struct next_rule_eth_prog_index_key));
  map_key.teid         = teid;
  map_key.source_value = source_value;
  map_key.ethertype = 0; // bpf_ntohs(eth->h_proto);

  // TODO [ETH-PDU] support other eth pkt filters
  struct next_rule_eth_prog_index_value* index_value = bpf_map_lookup_elem(&m_next_rule_eth_prog_index, &map_key);

  if (index_value) {
    // TODO [ETH-PDU] pdu sess info learn mac
    struct iphdr* iph_outer = (void*) (data + sizeof(struct ethhdr));

    if ((void*) iph_outer + sizeof(*iph_outer) > data_end) {
      bpf_debug("Invalid Outer IP packet");
      return XDP_DROP;
    }

    u32 src_ip_out = iph_outer->saddr;
    struct mac_pdu_session_value pdu_session;
    pdu_session.teid = index_value->teid_dl;
    pdu_session.ipv4_address = src_ip_out;
    bpf_map_update_elem(&m_mac_pdu_session, &eth->h_source, &pdu_session, BPF_NOEXIST);
    bpf_tail_call(ctx, &m_next_rule_prog, index_value->prog_id);
  }

  return XDP_PASS;
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
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;
  int action = XDP_PASS;

  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);

  // Check if the GTP header extends beyond the data end.
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("handle_uplink_traffic__eth_pdu: Invalid GTPU packet");
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
    bpf_debug("handle_uplink_traffic__eth_pdu: Invalid Ethernet packet");
    return XDP_DROP;
  }


  action = tail_call_next_prog__eth_pdu(ctx, gtpuh->teid, INTERFACE_VALUE_ACCESS, eth);

  return action;

}

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline u32 handle_downlink_traffic__eth_pdu(
    struct xdp_md* ctx) {
  bpf_debug("Handling downlink ETH PDU session traffic");
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;
  
  struct ethhdr* eth = data;
  if ((void*) eth + sizeof(*eth) > data_end) {
      bpf_debug("Invalid ETH packet");
      return XDP_DROP;
  }

  struct mac_pdu_session_value* pdu_session = bpf_map_lookup_elem(&m_mac_pdu_session, &eth->h_dest);
  if (pdu_session) {
     create_outer_header_gtpu(ctx, pdu_session->teid, pdu_session->ipv4_address, 1);
     return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
  }
  // Broadcast packet reach this point. Pass them TC
  // Check if destination MAC address is a broadcast address
  for (int i = 0; i < ETH_ALEN; i++) {
      if (eth->h_dest[i] != 0xFF) {
          goto out; // Not a broadcast address
      }
  }

  // This is a broadcast packet, prepare GTPU and send to TC layer
  // TODO: handle extension header not needed
  create_outer_header_gtpu(ctx, 0, 0, 1);
  return XDP_PASS;

out:
  bpf_debug("Could not find the ETH PDU session");
  return XDP_PASS;
}

static __always_inline int entry_point__eth_pdu(struct xdp_md* ctx) {
  bpf_debug("===== ETH PDU =======");
  void* data_end = (void*) (long) ctx->data_end;
  void* data = (void*) (long) ctx->data;
  int action = XDP_PASS;

  struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(struct ethhdr));
  if ((void*) (iph + 1) > data_end) {
      bpf_printk("xdp_entry_point__eth_pdu: Invalid IPv4 Packet");
      goto out;
  }

  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr* udph = (struct udphdr*) (iph + 1);

    // Check if the UDP header extends beyond the data end.
    if ((void*) (udph + 1) > data_end) {
      bpf_debug("xdp_entry_point__eth_pdu: Invalid UDP packet");
      action = XDP_DROP;
      goto out;
    }

    if (bpf_htons(udph->dest) == GTP_UDP_PORT) {
      bpf_debug("xdp_entry_point__eth_pdu: This is a GTP traffic");
      action = handle_uplink_traffic__eth_pdu(ctx, udph);
      goto out;
    }
  }

  action = handle_downlink_traffic__eth_pdu(ctx);

out:
  return action;
}

#endif /* __PFCP_SESSION_ETH_PDU_H */