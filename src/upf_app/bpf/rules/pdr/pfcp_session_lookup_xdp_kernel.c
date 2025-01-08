#define KBUILD_MODNAME pfcp_session_lookup_xdp_kernel

// clang-format off
#include <types.h>
// clang-format on
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <endian.h>
#include <lib/crc16.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <protocols/eth.h>
#include <protocols/gtpu.h>
#include <protocols/ip.h>
#include <protocols/udp.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <pfcp_session_lookup_maps.h>
#include <utils/logger.h>
#include <utils/utils.h>
#include <utils/gtpu_parse.h>
#include <next_prog_rule_key.h>
#include <mac_pdu_session_key.h>

#ifdef KERNEL_SPACE
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif
#include <stdio.h>

/* Defines xdp_stats_map */
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

/*****************************************************************************************************************/

static __always_inline u32 tail_call_next_prog(
    struct xdp_md* ctx, teid_t_ teid, u8 source_value, u32 ipv4_address) {
  struct next_rule_prog_index_key map_key;

  __builtin_memset(&map_key, 0, sizeof(struct next_rule_prog_index_key));
  map_key.teid         = teid;
  map_key.source_value = source_value;
  map_key.ipv4_address = ipv4_address;

  // Key for ETH filters
  bpf_printk("tail_call_next_prog: teid: %x - source_value: %u", map_key.teid, source_value);
  u32* index_prog = bpf_map_lookup_elem(&m_next_rule_prog_index, &map_key); // IP for ETH will need another map and new key

  if (index_prog) {
    bpf_debug("Value of the eBPF tail call, index_prog = %d", *index_prog);
    bpf_tail_call(ctx, &m_next_rule_prog, *index_prog);
  }

  bpf_debug("BPF tail call was not executed!");
  bpf_debug("Check your key and its endianess");

  return XDP_DROP;
}

/*---------------------------------------------------------------------------------------------------------------*/
// TODO [ETH-PDU] tail call for eth packet
static __always_inline u32 tail_call_next_eth_prog(
    struct xdp_md* ctx, teid_t_ teid, u8 source_value, struct ethhdr* eth) {
  bpf_debug("Executing tail call for eth pdu session");
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  // If inner packet is Ethernet broadcast (ff:ff:ff:ff:ff:ff) pass packet to TC
  if (eth->h_dest[0] == 0xff && eth->h_dest[1] == 0xff &&
      eth->h_dest[2] == 0xff && eth->h_dest[3] == 0xff &&
      eth->h_dest[4] == 0xff && eth->h_dest[5] == 0xff) {
      bpf_printk("Ethernet broadcast detected!\n");
      return XDP_PASS; // Drop broadcast packets (or take other action)
  }

  struct next_rule_eth_prog_index_key map_key;

  // Check types of maps and the keys that have to be included
  __builtin_memset(&map_key, 0, sizeof(struct next_rule_eth_prog_index_key));
  map_key.teid         = teid;
  map_key.source_value = source_value;
  map_key.ethertype = 0; // bpf_ntohs(eth->h_proto);

  // TODO [ETH-PDU] support other eth pkt filters
  bpf_printk("teid: %x - source_value: %u - ethertype: %x", map_key.teid, source_value, eth->h_proto);
  struct next_rule_eth_prog_index_value* index_value = bpf_map_lookup_elem(&m_next_rule_eth_prog_index, &map_key);

  if (index_value) {
    bpf_debug("Value of the eBPF tail call, index_prog = %d, tied = %d", index_value->prog_id, index_value->teid_dl);
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

  bpf_debug("BPF tail call was not executed!");
  // If downlink source value = INTERFACE_VALUE_CORE
  // Call program that will send based on destination i.e., ETH PDU session info

  bpf_debug("Check your key and its endianess");

  return XDP_DROP;
}

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline u32 handle_eth_downlink_traffic(
    struct xdp_md* ctx) {
  bpf_debug("Handling downlink ETH PDU session traffic");
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;
  
  struct ethhdr* eth = data;
  if ((void*) eth + sizeof(*eth) > data_end) {
      bpf_debug("Invalid ETH packet");
      return XDP_DROP;
  }
  bpf_debug("Dest MAC %x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);

  struct mac_pdu_session_value* pdu_session = bpf_map_lookup_elem(&m_mac_pdu_session, &eth->h_dest);
  if (pdu_session) {
    bpf_debug("Found the ETH PDU session");
     create_outer_header_gtpu_ipv4_eth(ctx, pdu_session);
     return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
  }
  // Broadcast packet reach this point. Pass them TC
  // Check if destination MAC address is a broadcast address
  for (int i = 0; i < ETH_ALEN; i++) {
      if (eth->h_dest[i] != 0xFF) {
          goto out; // Not a broadcast address
      }
  }
  bpf_debug("This is a broadcast packet, prepare GTPU and send to TC layer");
  struct mac_pdu_session_value pdu = {};
  __builtin_memset(&pdu, 0, sizeof(struct mac_pdu_session_value));
  // TODO: handle extension header not needed
  create_outer_header_gtpu_ipv4_eth(ctx, &pdu);
  return XDP_PASS;

  // Should rather have a single FAR program for ETH PDU sessions. Then call this program every time.
  
  // TODO [ETH-PDU] implement routing based on learned MAC

out:
  bpf_debug("Could not find the ETH PDU session");
  return XDP_PASS;
}

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline u32
handle_downlink_traffic(struct xdp_md* ctx, u32 ue_ip_address) {
  bpf_debug("Handling downlink traffic");
  u32* teid_dl = bpf_map_lookup_elem(&m_session_mapping, &ue_ip_address);
  u32 ret = XDP_PASS;
  if (teid_dl) {
    bpf_debug(
        "TEID downlink: 0x%x was found for UE IP: 0x%x", ue_ip_address,
        *teid_dl);
    tail_call_next_prog(ctx, *teid_dl, INTERFACE_VALUE_CORE, ue_ip_address);
  }

  // NOTE: The IP of the ETH PDU session needs to be a different subnet from UE allocated IPs
  // If teid_dl is not found, this can be ETH packet.
  // TODO [ETH-PDU] support ETH PDU sessions DL using packet filters. Currently only using ETH PDU sess info for DL
  ret = handle_eth_downlink_traffic(ctx);

  bpf_debug("BPF tail call was not executed!");

  return ret;
}

/*---------------------------------------------------------------------------------------------------------------*/
/**
 * Uplink SECTION.
 */

/**
 * @brief Handle UDP header.
 *
 * @param ctx The user accessible metadata for xdp packet hook.
 * @param udph The UDP header.
 * @return u32 The XDP action.
 */

static __always_inline u32
handle_uplink_traffic(struct xdp_md* ctx, struct udphdr* udph) {
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);

  // Check if the GTP header extends beyond the data end.
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("Invalid GTPU packet");
    return XDP_DROP;
  }

  struct ethhdr* ethh_new = data + GTP_ENCAPSULATED_SIZE;

  if ((void*) ethh_new + sizeof(*ethh_new) > data_end) {
    bpf_debug("Invalid Ethernet packet");
    return XDP_DROP;
  }

  // Only run 
  // TODO [ETH-PDU] if eth pdu then there is no need to go down
  // Implement a method to check session type first
  // Check if IP else check ETH

  struct iphdr* iph_inner = (void*) (ethh_new + 1);

  if ((void*) iph_inner + sizeof(*iph_inner) > data_end) {
    bpf_debug("Invalid Inner IP packet");
    return XDP_DROP;
  }

  if (!(iph_inner->version == 4 || iph_inner->version == 6)) { // Not IP packet
    bpf_debug("Not an IP packet, attempting ETH PDU");
    struct ethhdr* eth = (void*) (ethh_new + 1);

    tail_call_next_eth_prog(ctx, gtpuh->teid, INTERFACE_VALUE_ACCESS, eth);

    return XDP_PASS;
  }

  bpf_debug("IP packet, attempting IP PDU");
  u32 src_ip_in = iph_inner->saddr;

  if (gtpuh->message_type != GTPU_G_PDU) {
    bpf_debug(
        "Message type 0x%x is not GTPU GPDU(0x%x)\n", gtpuh->message_type,
        GTPU_G_PDU);
    return XDP_PASS;
  }

  // Jump to session context.
  tail_call_next_prog(ctx, gtpuh->teid, INTERFACE_VALUE_ACCESS, src_ip_in);

  return XDP_PASS;
}

/*---------------------------------------------------------------------------------------------------------------*/

/**
 * IP SECTION.
 */

/**
 * @brief Handle IPv4 header.
 *
 * @param ctx The user accessible metadata for xdp packet hook.
 * @param iph The IP header.
 * @return u32 The XDP action.
 */

static __always_inline u32 ipv4_handle(struct xdp_md* ctx, struct iphdr* iph) {
  void* data_end = (void*) (long) ctx->data_end;

  u32 ip_dest = iph->daddr;
  u8 protocol = iph->protocol;

  switch (protocol) {
    case IPPROTO_UDP: {
      struct udphdr* udph = (struct udphdr*) (iph + 1);

      // Check if the UDP header extends beyond the data end.
      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Invalid UDP packet");
        return XDP_DROP;
      }

      if (bpf_htons(udph->dest) == GTP_UDP_PORT) {
        bpf_debug("This is a GTP traffic");
        return handle_uplink_traffic(ctx, udph);
      }
    }
    default: {
      return handle_downlink_traffic(ctx, ip_dest);
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
/**
 * ETHERNET SECTION.
 */

/**
 *
 * @brief Parse Ethernet layer 2, extract network layer 3 offset and protocol
 * Call next protocol handler (e.g. ipv4).
 *
 * @param ctx
 * @param ethh
 * @return u32 The XDP action.
 */

static __always_inline u32 eth_handle(struct xdp_md* ctx, struct ethhdr* ethh) {
  void* data_end = (void*) (long) ctx->data_end;
  u16 eth_type   = bpf_htons(ethh->h_proto);
  u64 offset     = sizeof(*ethh);

  bpf_debug("Debug: eth_type:0x%x", eth_type);

  switch (eth_type) {
    case ETH_P_IP: {
      struct iphdr* iph = (struct iphdr*) ((void*) ethh + offset);

      if ((void*) (iph + 1) > data_end) {
        bpf_debug("Invalid IPv4 Packet");
        return XDP_DROP;
      }

      return ipv4_handle(ctx, iph);
    }
    case ETH_P_8021AD: {
      bpf_debug("VLAN!! Changing the offset");
      struct vlan_hdr* vlan_hdr = (struct vlan_hdr*) (ethh + 1);
      offset += sizeof(*vlan_hdr);
      if ((void*) (vlan_hdr + 1) <= data_end)
        eth_type = bpf_htons(vlan_hdr->h_vlan_encapsulated_proto);
    }
    case ETH_P_IPV6:
    case ETH_P_ARP:
    case ETH_P_8021Q:
    default: {
      bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x", offset, eth_type);
      return XDP_PASS;
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
SEC("xdp")
int xdp_entry_point(struct xdp_md* ctx) {
  bpf_debug("================< PFCP PDR Sesction >================");
  struct ethhdr* ethh = (void*) (long) ctx->data;

  if ((void*) (ethh + 1) > (void*) (long) ctx->data_end) {
    bpf_debug("Invalid Ethernet header");
    return XDP_DROP;
  }

  return eth_handle(ctx, ethh);
}

/*---------------------------------------------------------------------------------------------------------------*/
SEC("xdp")
int xdp_entry_point_downlink(struct xdp_md* ctx) {
  bpf_debug("================< PFCP PDR DL Sesction >================");
  void* data_end = (void*) (long) ctx->data_end;
  struct ethhdr* ethh = (void*) (long) ctx->data;
  u64 offset     = sizeof(*ethh);

  if ((void*) (ethh + 1) > (void*) (long) ctx->data_end) {
    bpf_debug("Invalid Ethernet header");
    return XDP_DROP;
  }
  u16 eth_type   = bpf_htons(ethh->h_proto);

  switch (eth_type) {
    case ETH_P_IP: {
      struct iphdr* iph = (struct iphdr*) ((void*) ethh + offset);

      if ((void*) (iph + 1) > data_end) {
        bpf_debug("Invalid IPv4 Packet");
        return XDP_DROP;
      }

      return ipv4_handle(ctx, iph);
    }
    case ETH_P_8021AD: {
      bpf_debug("VLAN!! Changing the offset");
      struct vlan_hdr* vlan_hdr = (struct vlan_hdr*) (ethh + 1);
      offset += sizeof(*vlan_hdr);
      if ((void*) (vlan_hdr + 1) <= data_end)
        eth_type = bpf_htons(vlan_hdr->h_vlan_encapsulated_proto);
    }
    case ETH_P_ARP: {
      bpf_debug("Handling ARP packet ctx->ingress_ifindex  = %d", ctx->ingress_ifindex);
      handle_eth_downlink_traffic(ctx);
      return XDP_PASS;
    }
    case ETH_P_IPV6:
    case ETH_P_8021Q:
    default: {
      bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x", offset, eth_type);
      return XDP_PASS;
    }
  }
}

char _license[] SEC("license") = "GPL";

/*---------------------------------------------------------------------------------------------------------------*/