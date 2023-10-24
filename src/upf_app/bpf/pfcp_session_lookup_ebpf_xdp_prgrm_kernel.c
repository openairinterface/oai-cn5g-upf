#define KBUILD_MODNAME pfcp_session_lookup_ebpf_xdp_prgrm_kernel

// clang-format off
#include <types.h>
// clang-format on
#include <bpf_helpers.h>
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
#include <next_prog_rule_key.h>
//#include <traffic_classification.h>
//#include <qfi_flow_mapping_table.h>

#ifdef KERNEL_SPACE
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif
#include <stdio.h>
/* Defines xdp_stats_map */
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

/*****************************************************************************************************************/

static u32 tail_call_next_prog(
    struct xdp_md* p_ctx, teid_t_ teid, u8 source_value, u32 ipv4_address) {
  struct next_rule_prog_index_key map_key;

  __builtin_memset(&map_key, 0, sizeof(struct next_rule_prog_index_key));
  map_key.teid         = teid;
  map_key.source_value = source_value;
  map_key.ipv4_address = ipv4_address;

  bpf_debug(
      "Packet Informations (TEID: 0x%x, SRC INTERFACE: %d, IP: 0x%x)", teid,
      source_value, ipv4_address);

  // return XDP_DROP;

  u32* index_prog = bpf_map_lookup_elem(&m_next_rule_prog_index, &map_key);

  if (index_prog) {
    bpf_debug("Value of the eBPF tail call, index_prog = %d", *index_prog);
    bpf_tail_call(p_ctx, &m_next_rule_prog, *index_prog);
  }

  bpf_debug("BPF tail call was not executed!");
  bpf_debug("Check your key and its endianess");

  return XDP_DROP;
}

/*****************************************************************************************************************/

static u32 handle_downlink_traffic(struct xdp_md* p_ctx, u32 ue_ip_address) {
  // u32* teid_dl = NULL;

  u32* teid_dl = bpf_map_lookup_elem(&m_session_mapping, &ue_ip_address);

  if (teid_dl) {
    bpf_printk(
        "TEID downlink: 0x%x was found for UE IP: 0x%x", ue_ip_address,
        *teid_dl);
    tail_call_next_prog(p_ctx, *teid_dl, INTERFACE_VALUE_CORE, ue_ip_address);
  }

  bpf_debug("BPF tail call was not executed!");

  return XDP_PASS;
}

/*****************************************************************************************************************/
/**
 * Uplink SECTION.
 */

/**
 * @brief Handle UDP header.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param udph The UDP header.
 * @return u32 The XDP action.
 */

static u32 handle_uplink_traffic(struct xdp_md* p_ctx, struct udphdr* udph) {
  void* p_data     = (void*) (long) p_ctx->data;
  void* p_data_end = (void*) (long) p_ctx->data_end;

  struct gtpuhdr* p_gtpuh = (struct gtpuhdr*) (udph + 1);

  // Check if the GTP header extends beyond the data end.
  if ((void*) p_gtpuh + sizeof(*p_gtpuh) > p_data_end) {
    bpf_debug("Invalid GTPU packet");
    return XDP_DROP;
  }

  struct ethhdr* p_new_eth = p_data + GTP_ENCAPSULATED_SIZE;

  if ((void*) p_new_eth + sizeof(*p_new_eth) > p_data_end) {
    bpf_debug("Invalid Ethernet packet");
    return XDP_DROP;
  }

  struct iphdr* p_ip_inner = (void*) (p_new_eth + 1);

  if ((void*) p_ip_inner + sizeof(*p_ip_inner) > p_data_end) {
    bpf_debug("Invalid Inner IP packet");
    return XDP_DROP;
  }

  u32 src_ip_in = p_ip_inner->saddr;

  if (p_gtpuh->message_type != GTPU_G_PDU) {
    // bpf_debug(
    //     "Message type 0x%x is not GTPU GPDU(0x%x)\n", p_gtpuh->message_type,
    //     GTPU_G_PDU);
    return XDP_PASS;
    // return XDP_DROP;
  }

  // bpf_debug("GTP GPDU received with Valid GTP Packet (SRC IP:0x%x)\n",
  // src_ip);

  // Check if the gtp extension header extends beyond the data end.
  // if ((void*) ((struct gtpu_extn_pdu_session_container*) (p_gtpuh + 1) + 1) >
  //     (void*) (long) p_ctx->data_end) {
  //  // bpf_debug("Invalid IPv4 Inner Header\n");
  //   return XDP_DROP;
  // }

  // Jump to session context.
  tail_call_next_prog(p_ctx, p_gtpuh->teid, INTERFACE_VALUE_ACCESS, src_ip_in);
  // bpf_debug("BPF tail call was not executed! teid %d\n", p_gtpuh->teid);

  return XDP_PASS;
}

/*****************************************************************************************************************/

/**
 * IP SECTION.
 */

/**
 * @brief Handle IPv4 header.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param iph The IP header.
 * @return u32 The XDP action.
 */

static u32 ipv4_handle(struct xdp_md* p_ctx, struct iphdr* iph) {
  void* p_data_end = (void*) (long) p_ctx->data_end;

  u32 ip_dest = iph->daddr;
  u8 protocol = iph->protocol;

  switch (protocol) {
    case IPPROTO_UDP: {
      struct udphdr* udph = (struct udphdr*) (iph + 1);

      // Check if the UDP header extends beyond the data end.
      if ((void*) (udph + 1) > p_data_end) {
        bpf_printk("Invalid UDP packet");
        return XDP_DROP;
      }

      if (htons(udph->dest) == GTP_UDP_PORT) {
        bpf_printk("This is a GTP traffic");
        return handle_uplink_traffic(p_ctx, udph);
      }
    }
    default: {
      return handle_downlink_traffic(p_ctx, ip_dest);
    }
  }
}

/*****************************************************************************************************************/
/**
 * ETHERNET SECTION.
 */

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

/**
 *
 * @brief Parse Ethernet layer 2, extract network layer 3 offset and protocol
 * Call next protocol handler (e.g. ipv4).
 *
 * @param p_ctx
 * @param ethh
 * @return u32 The XDP action.
 */

static u32 eth_handle(struct xdp_md* p_ctx, struct ethhdr* ethh) {
  void* p_data_end = (void*) (long) p_ctx->data_end;
  u16 eth_type     = htons(ethh->h_proto);
  u64 offset       = sizeof(*ethh);

  bpf_debug("Debug: eth_type:0x%x", eth_type);

  switch (eth_type) {
    case ETH_P_8021Q:
    case ETH_P_8021AD: {
      bpf_debug("VLAN!! Changing the offset");
      struct vlan_hdr* vlan_hdr = (struct vlan_hdr*) (ethh + 1);
      offset += sizeof(*vlan_hdr);
      if ((void*) (vlan_hdr + 1) <= p_data_end)
        eth_type = htons(vlan_hdr->h_vlan_encapsulated_proto);
    }
    case ETH_P_IP: {
      struct iphdr* iph = (struct iphdr*) ((void*) ethh + offset);

      // Check if the IP header extends beyond the data end.
      if ((void*) (iph + 1) > p_data_end) {
        bpf_debug("Invalid IPv4 Packet");
        return XDP_DROP;
      }

      return ipv4_handle(p_ctx, iph);
    }
    case ETH_P_IPV6:
    // Skip non 802.3 Ethertypes
    case ETH_P_ARP:
      // Skip non 802.3 Ethertypes
      // Fall-through
      return XDP_PASS;
    default:
      bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x", offset, eth_type);
      return XDP_PASS;
      // return XDP_DROP; //bpf_debug("Drop the packet"); // I cannot drop the
      // packet due to arping not handeled
  }
}

/*****************************************************************************************************************/
SEC("xdp_entry_point")
int entry_point(struct xdp_md* p_ctx) {
  bpf_debug("==========< PFCP Session Lookup >==========");

  struct ethhdr* ethh = (void*) (long) p_ctx->data;

  if ((void*) (ethh + 1) > (void*) (long) p_ctx->data_end) {
    bpf_debug("Invalid Ethernet header");
    return XDP_DROP;
  }

  return xdp_stats_record_action(p_ctx, eth_handle(p_ctx, ethh));
}

char _license[] SEC("license") = "GPL";

/*****************************************************************************************************************/