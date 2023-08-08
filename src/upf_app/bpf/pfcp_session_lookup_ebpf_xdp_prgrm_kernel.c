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
#include <traffic_classification.h>
#include <qfi_flow_mapping_table.h>
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
      "Packet Informations (TEID: %d, SRC INTERFACE: %d, IP SRC: 0x%x)\n", teid,
      source_value, ipv4_address);

  u32* index_prog = bpf_map_lookup_elem(&m_next_rule_prog_index, &map_key);

  if (index_prog) {
    bpf_debug("Value of the eBPF tail call, index_prog = %d\n", *index_prog);
    bpf_tail_call(p_ctx, &m_next_rule_prog, *index_prog);
  }

  bpf_debug("BPF tail call was not executed!\n");
  bpf_debug("Check your key and its endianess\n");

  return XDP_DROP;
}

/*****************************************************************************************************************/

static u32 update_map_traffic_classification(
    u32 src_ip, u8 protocol, u32 dest_ip, u32 teid_dl) {
  struct s_traffic key;
  __builtin_memset(&key, 0, sizeof(struct s_traffic));

  key.src_ip   = src_ip;
  key.protocol = protocol;
  key.dest_ip  = dest_ip;

  bpf_map_update_elem(&m_traffic_classification, &key, &teid_dl, BPF_ANY);

  return 0;
}

/*****************************************************************************************************************/

static u32* get_teid_downlink_from_traffic_class_map(
    u32 src_ip, u32 dest_ip, u8 protocol) {
  struct s_traffic key_traffic_class = {0};

  key_traffic_class.src_ip   = src_ip;
  key_traffic_class.protocol = protocol;
  key_traffic_class.dest_ip  = dest_ip;

  u32* teid_dl =
      bpf_map_lookup_elem(&m_traffic_classification, &key_traffic_class);
  return teid_dl;
}

/*****************************************************************************************************************/

// static struct s_qfi_parameters* get_qfi_params_from_qos_flow_map(u8 dscp) {
//   struct s_qfi_parameters* qfi_param =
//       bpf_map_lookup_elem(&m_qos_flow_map, &dscp);
//   return qfi_param;
// }

/*****************************************************************************************************************/

static u32* get_teid_uplink_from_ue_qfi_teid_map(u32 dest_ip, u8 qfi) {
  struct s_ue_qfi key_ue_qfi = {0};
  key_ue_qfi.src_ip          = dest_ip;
  key_ue_qfi.qfi             = qfi;
  return bpf_map_lookup_elem(&m_ue_qfi_teid, &key_ue_qfi);
}

/*****************************************************************************************************************/

// static u32* get_teid_uplink_from_ue_qfi_teid_map(u32 dest_ip, u8 dscp) {
//   struct s_qfi_parameters* qfi_params =
//   get_qfi_params_from_qos_flow_map(dscp);

//   if (qfi_params) {
//     u8 qfi = qfi_params->qfi;
//     bpf_debug("QFI %d was found for dscp %d", qfi, dscp);
//      struct s_ue_qfi key_ue_qfi = {0};
//     key_ue_qfi.src_ip          = dest_ip;
//     key_ue_qfi.qfi             = qfi;

//     u32* teid_ul = bpf_map_lookup_elem(&m_ue_qfi_teid, &key_ue_qfi);
//     u32 teid_val = 1;
//     teid_ul = &teid_val;
//     return teid_ul;
//   }
// }
/*****************************************************************************************************************/

// static u32* get_teid_downlink_session(u32 dest_ip, u32 teid_ul) {
//   struct s_session_mapping key_session_mapping;
//   __builtin_memset(&key_session_mapping, 0, sizeof(struct
//   s_session_mapping)); key_session_mapping.ue_ip_address = dest_ip;
//   key_session_mapping.teid_ul       = teid_ul;

//   u32* teid_dl = bpf_map_lookup_elem(&m_session_mapping,
//   &key_session_mapping); return teid_dl;
// }

static u32* get_teid_downlink_session(u32 dest_ip, u32 teid_ul) {
  struct s_session_mapping key_session_mapping;
  __builtin_memset(&key_session_mapping, 0, sizeof(struct s_session_mapping));
  key_session_mapping.teid_ul       = teid_ul,
  key_session_mapping.ue_ip_address = dest_ip;
  return bpf_map_lookup_elem(&m_session_mapping, &key_session_mapping);
}

/*****************************************************************************************************************/

// static u32* get_teid_downlink_from_qfi_and_teid_ul_(
//     u32 src_ip, u32 dest_ip, u8 dscp, u8 protocol) {
//   u32* teid_dl = NULL;
//   u32* teid_ul = get_teid_uplink_from_ue_qfi_teid_map(dest_ip, dscp);

//     if (teid_ul) {
//       bpf_debug(
//           "Teid Uplink %d was found in QFI Flow Table (src ip, dscp) = (%d, "
//           "%u)",
//           *teid_ul, dest_ip, dscp);
//       teid_dl = get_teid_downlink_session(dest_ip, *teid_ul);

//       if (teid_dl) {
//         update_map_traffic_classification(src_ip, protocol, dest_ip,
//         *teid_dl);
//         //bpf_debug("The teid for downlink: %d", *teid_dl);
//       }
//     }

//   return teid_dl;
// }
/*****************************************************************************************************************/

static u32 retreive_teid_downlink(
    struct xdp_md* p_ctx, u32 src_ip, u32 dest_ip, u8 dscp, u8 protocol) {
  u32* teid_dl = NULL;

  teid_dl = get_teid_downlink_from_traffic_class_map(src_ip, dest_ip, protocol);

  if (teid_dl) {
    tail_call_next_prog(p_ctx, *teid_dl, INTERFACE_VALUE_CORE, dest_ip);
    bpf_printk("Tail call was not executed, drop the packet");
    return XDP_DROP;
  }

  bpf_printk("No TEID Downlink was found for traffic class");

  struct s_qfi_parameters* qfi_params =
      bpf_map_lookup_elem(&m_qos_flow_map, &dscp);

  if (!qfi_params) {
    bpf_printk("QFI was not found for dscp %d", dscp);
    return XDP_DROP;
  }

  u8 qfi       = qfi_params->qfi;
  u32* teid_ul = get_teid_uplink_from_ue_qfi_teid_map(dest_ip, qfi);

  if (!teid_ul) {
    bpf_printk(
        "Teid Uplink was not found in QFI Flow Table (src ip, dscp) =(%d, %u)",
        dest_ip, dscp);
    return XDP_DROP;
  }

  bpf_printk("Teid Uplink %d was found in ...", *teid_ul);

  teid_dl = get_teid_downlink_session(dest_ip, *teid_ul);

  if (!teid_dl) {
    bpf_printk("No TEID downlink found for UE IP SRC: %d", dest_ip);
    bpf_printk("And for TEID_UL: %d", *teid_ul);
    return XDP_DROP;
  }

  update_map_traffic_classification(src_ip, protocol, dest_ip, *teid_dl);

  tail_call_next_prog(p_ctx, *teid_dl, INTERFACE_VALUE_CORE, dest_ip);
  bpf_printk("Tail call was not executed, drop the packet");
  return XDP_DROP;
}

// u32 teid_value = 1107610522;
// u32* teid_dl = &teid_value;

/*****************************************************************************************************************/

/**
 * GTP SECTION.
 */

/**
 * @brief Check if GTP packet is a GPDU. If so, process the next block chain.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param p_gtpuh The GTP header.
 * @return u32 The XDP action.
 */

static u32 gtp_handle(
    struct xdp_md* p_ctx, struct gtpuhdr* p_gtpuh, u32 src_ip) {
  // TODO: Handle other PDU.
  if (p_gtpuh->message_type != GTPU_G_PDU) {
    bpf_debug(
        "Message type 0x%x is not GTPU GPDU(0x%x)\n", p_gtpuh->message_type,
        GTPU_G_PDU);
    return XDP_PASS;
    // return XDP_DROP;
  }

  bpf_debug("GTP GPDU received with Valid GTP Packet (SRC IP:0x%x)\n", src_ip);

  // Check if the gtp extension header extends beyond the data end.
  if ((void*) ((struct gtpu_extn_pdu_session_container*) (p_gtpuh + 1) + 1) >
      (void*) (long) p_ctx->data_end) {
    bpf_debug("Invalid IPv4 Inner Header\n");
    return XDP_DROP;
  }

  // Jump to session context.
  tail_call_next_prog(p_ctx, p_gtpuh->teid, INTERFACE_VALUE_ACCESS, src_ip);
  bpf_debug("BPF tail call was not executed! teid %d\n", p_gtpuh->teid);

  return XDP_PASS;
  // return XDP_DROP;
}

/*****************************************************************************************************************/
/**
 * UDP SECTION.
 */

/**
 * @brief Handle UDP header.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param udph The UDP header.
 * @return u32 The XDP action.
 */

static u32 udp_handle(
    struct xdp_md* p_ctx, struct udphdr* udph, u32 src_ip, u32 dest_ip,
    u8 dscp) {
  void* p_data     = (void*) (long) p_ctx->data;
  void* p_data_end = (void*) (long) p_ctx->data_end;
  bpf_debug("*** IP DST: %d", dest_ip);
  u32 dport = htons(udph->dest);

  switch (dport) {
    case GTP_UDP_PORT: {
      struct gtpuhdr* p_gtpuh = (struct gtpuhdr*) (udph + 1);

      // Check if the GTP header extends beyond the data end.
      if ((void*) (p_gtpuh + 1) > p_data_end) {
        bpf_debug("Invalid GTPU packet\n");
        return XDP_DROP;
      }

      struct ethhdr* p_new_eth = p_data + GTP_ENCAPSULATED_SIZE;

      if ((void*) (p_new_eth + 1) > p_data_end) {
        return XDP_DROP;
      }

      struct iphdr* p_ip_inner = (void*) (p_new_eth + 1);

      if ((void*) (p_ip_inner + 1) > p_data_end) {
        return XDP_DROP;
      }

      u32 src_ip_in = p_ip_inner->saddr;
      return gtp_handle(p_ctx, p_gtpuh, src_ip_in);
    }
    default: {
      // The destination IP is the UE IP address (donwlink).
      //   u32* teid_dl = retreive_teid_downlink(src_ip, dest_ip, dscp,
      //   IPPROTO_UDP);

      //   if (teid_dl) {
      //     bpf_debug("The teid for downlink UDP: %d", *teid_dl);
      //     update_map_traffic_classification(
      //         src_ip, IPPROTO_UDP, dest_ip, *teid_dl);
      //     tail_call_next_prog(p_ctx, *teid_dl, INTERFACE_VALUE_CORE,
      //     dest_ip); bpf_debug("BPF tail call was not executed! teid %d\n",
      //     teid_dl); return XDP_PASS;
      //   }

      //   bpf_debug(
      //       "No TEID Downlink was foud for (src ip, dest ip) = (%d, %d)",
      //       src_ip, dest_ip);
      //   bpf_debug("and for (protocol, dscp) = (%u, %u)", IPPROTO_UDP, dscp);
      //   return XDP_DROP;
      // retreive_teid_downlink(p_ctx, src_ip, dest_ip, dscp, IPPROTO_UDP);
    }
  }
}

/*****************************************************************************************************************/
/**
 * TCP SECTION.
 */

/**
 * @brief Handle TCP header.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param tcph The TCP header.
 * @return u32 The XDP action.
 */
static u32 tcp_handle(
    struct xdp_md* p_ctx, struct tcphdr* tcph, u32 src_ip, u32 dest_ip,
    u8 dscp) {
  // bpf_debug("Valid TCP Packet (SRC IP:0x%x, DEST IP:0x%x)\n", src_ip,
  // dest_ip); u32* teid_dl = retreive_teid_downlink(src_ip, dest_ip, dscp,
  // IPPROTO_TCP);

  // if (teid_dl) {
  //   bpf_debug("The teid for downlink TCP: %d", *teid_dl);
  //   update_map_traffic_classification(src_ip, IPPROTO_TCP, dest_ip,
  //   *teid_dl); tail_call_next_prog(p_ctx, *teid_dl, INTERFACE_VALUE_CORE,
  //   dest_ip); bpf_debug("BPF tail call was not executed! teid %d\n",
  //   teid_dl); return XDP_PASS;
  // }

  // bpf_debug(
  //     "No TEID Downlink was foud for (src ip, dest ip) = (%d, %d)", src_ip,
  //     dest_ip);
  // bpf_debug("and for (protocol, dscp) = (%u, %u)", IPPROTO_TCP, dscp);
  // return XDP_DROP;
  // retreive_teid_downlink(p_ctx, src_ip, dest_ip, dscp, IPPROTO_TCP);
}

/*****************************************************************************************************************/
/**
 * ICMP SECTION.
 */

/**
 * @brief Handle ICMP header.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param icmph The icmp header.
 * @return u32 The XDP action.
 */

static u32 icmp_handle(
    struct xdp_md* p_ctx, struct icmphdr* icmph, u32 src_ip, u32 dest_ip,
    u8 dscp) {
  // u32* teid_dl = retreive_teid_downlink(src_ip, dest_ip, dscp, IPPROTO_ICMP);

  // if (teid_dl) {
  //   bpf_debug("The teid for downlink ICMP: %d", *teid_dl);
  //   update_map_traffic_classification(src_ip, IPPROTO_ICMP, dest_ip,
  //   *teid_dl); tail_call_next_prog(p_ctx, *teid_dl, INTERFACE_VALUE_CORE,
  //   dest_ip); bpf_debug("BPF tail call was not executed! teid %d\n",
  //   teid_dl); return XDP_PASS;
  // }

  // bpf_debug(
  //     "No TEID Downlink was foud for (src ip, dest ip) = (%d, %d)", src_ip,
  //     dest_ip);
  // bpf_debug("and for (protocol, dscp) = (%u, %u)", IPPROTO_ICMP, dscp);
  // return XDP_DROP;
  // retreive_teid_downlink(p_ctx, src_ip, dest_ip, dscp, IPPROTO_ICMP);
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
  void* p_data     = (void*) (long) p_ctx->data;
  void* p_data_end = (void*) (long) p_ctx->data_end;

  u32 ip_dest = iph->daddr;
  u32 ip_src  = iph->saddr;
  u8 dscp     = iph->tos;
  u8 protocol = iph->protocol;
  // bpf_debug("icmp src ip = %d", ip_src);
  // bpf_debug("icmp dst ip = %d", ip_dest);
  // bpf_debug("icmp dscp ip = %u", dscp);

  switch (iph->protocol) {
    case IPPROTO_UDP: {
      bpf_debug("*** This is a UDP packet ***\n");
      struct udphdr* udph = (struct udphdr*) (iph + 1);

      // Check if the UDP header extends beyond the data end.
      if ((void*) (udph + 1) > p_data_end) {
        bpf_debug("Invalid UDP packet\n");
        return XDP_DROP;
      }

      u32 dport = htons(udph->dest);

      if (dport == GTP_UDP_PORT) {
        struct gtpuhdr* p_gtpuh = (struct gtpuhdr*) (udph + 1);

        // Check if the GTP header extends beyond the data end.
        if ((void*) (p_gtpuh + 1) > p_data_end) {
          bpf_debug("Invalid GTPU packet\n");
          return XDP_DROP;
        }

        struct ethhdr* p_new_eth = p_data + GTP_ENCAPSULATED_SIZE;

        if ((void*) (p_new_eth + 1) > p_data_end) {
          return XDP_DROP;
        }

        struct iphdr* p_ip_inner = (void*) (p_new_eth + 1);

        if ((void*) (p_ip_inner + 1) > p_data_end) {
          return XDP_DROP;
        }

        u32 src_ip_in = p_ip_inner->saddr;
        return gtp_handle(p_ctx, p_gtpuh, src_ip_in);
      }

      //      return udp_handle(p_ctx, udph, ip_src, ip_dest, dscp);
      break;
    }
    case IPPROTO_TCP: {
      bpf_debug("*** This is a TCP packet ***\n");
      // tail_call_next_prog(p_ctx, 1, INTERFACE_VALUE_ACCESS, 201392387);
      break;
    }
    case IPPROTO_ICMP: {
      bpf_debug("*** This is an ICMP packet ***\n");
      // tail_call_next_prog(p_ctx, 2, INTERFACE_VALUE_CORE, 201392399);
      break;
    }
    default: {
      bpf_debug("Non UDP/TCP/ICMP protocols\n");
      // return XDP_PASS;
      return XDP_DROP;
    }
  }

  retreive_teid_downlink(p_ctx, ip_src, ip_dest, dscp, protocol);
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

  bpf_debug("Debug: eth_type:0x%x\n", eth_type);

  switch (eth_type) {
    case ETH_P_8021Q:
    case ETH_P_8021AD: {
      bpf_debug("VLAN!! Changing the offset\n");
      struct vlan_hdr* vlan_hdr = (struct vlan_hdr*) (ethh + 1);
      offset += sizeof(*vlan_hdr);
      if ((void*) (vlan_hdr + 1) <= p_data_end)
        eth_type = htons(vlan_hdr->h_vlan_encapsulated_proto);
    }
    case ETH_P_IP: {
      struct iphdr* iph = (struct iphdr*) ((void*) ethh + offset);
      // Check if the IP header extends beyond the data end.
      if ((void*) (iph + 1) > p_data_end) {
        bpf_debug("Invalid IPv4 Packet\n");
        return XDP_DROP;
      }

      return ipv4_handle(p_ctx, iph);
    }
    case ETH_P_IPV6:
    // Skip non 802.3 Ethertypes
    case ETH_P_ARP:
    // Skip non 802.3 Ethertypes
    // Fall-through
    default:
      bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n", offset, eth_type);
      return XDP_PASS;
      // return XDP_DROP; //bpf_debug("Drop the packet"); // I can not drop the
      // packet due to arping not handeled
  }
}

/*****************************************************************************************************************/
SEC("xdp_entry_point")
int entry_point(struct xdp_md* p_ctx) {
  bpf_debug("==========< PFCP Session Lookup >==========\n");

  struct ethhdr* ethh = (void*) (long) p_ctx->data;

  if ((void*) (ethh + 1) > (void*) (long) p_ctx->data_end) {
    bpf_debug("Invalid Ethernet header\n");
    return XDP_DROP;
  }

  return xdp_stats_record_action(p_ctx, eth_handle(p_ctx, ethh));
}

char _license[] SEC("license") = "GPL";

/*****************************************************************************************************************/

// #define IPPROTO_IP		IPPROTO_IP
// #define IPPROTO_ICMP		IPPROTO_ICMP
// #define IPPROTO_IGMP		IPPROTO_IGMP
// #define IPPROTO_IPIP		IPPROTO_IPIP
// #define IPPROTO_TCP		IPPROTO_TCP
// #define IPPROTO_EGP		IPPROTO_EGP
// #define IPPROTO_PUP		IPPROTO_PUP
// #define IPPROTO_UDP		IPPROTO_UDP
// #define IPPROTO_IDP		IPPROTO_IDP
// #define IPPROTO_TP		IPPROTO_TP
// #define IPPROTO_DCCP		IPPROTO_DCCP
// #define IPPROTO_IPV6		IPPROTO_IPV6
// #define IPPROTO_RSVP		IPPROTO_RSVP
// #define IPPROTO_GRE		IPPROTO_GRE
// #define IPPROTO_ESP		IPPROTO_ESP
// #define IPPROTO_AH		IPPROTO_AH
// #define IPPROTO_MTP		IPPROTO_MTP
// #define IPPROTO_BEETPH		IPPROTO_BEETPH
// #define IPPROTO_ENCAP		IPPROTO_ENCAP
// #define IPPROTO_PIM		IPPROTO_PIM
// #define IPPROTO_COMP		IPPROTO_COMP
// #define IPPROTO_SCTP		IPPROTO_SCTP
// #define IPPROTO_UDPLITE		IPPROTO_UDPLITE
// #define IPPROTO_MPLS		IPPROTO_MPLS
// #define IPPROTO_RAW		IPPROTO_RAW
