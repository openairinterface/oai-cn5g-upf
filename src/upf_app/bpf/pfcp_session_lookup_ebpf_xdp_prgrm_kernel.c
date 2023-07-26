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
//#include <bpf/bpf.h>

#ifdef KERNEL_SPACE
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif

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
  
  //return XDP_DROP;

  u32* index_prog = bpf_map_lookup_elem(&m_next_rule_prog_index, &map_key);

  if (index_prog) {
    bpf_debug("Value of the eBPF tail call, index_prog = %d\n", *index_prog);
    bpf_tail_call(p_ctx, &m_next_rule_prog, *index_prog);
    bpf_debug("BPF tail call was not executed!\n");
  }

  //return XDP_DROP;

  bpf_debug("BPF tail call was not executed!\n");
  bpf_debug("One reason could be:\n");
  bpf_debug(
      "1. Key values not matching hash key for map m_next_rule_prog!\n \
             \t\t\t\t\t\t You have to compare the keys\n \
             \t\t\t\t\t\t 2. Endianess problem!\n \
             \t\t\t\t\t\t Map and Key values are saved in different endianess!\n\
             \t\t\t\t\t\t Map Hash Key and Key not matching\n");

  return XDP_DROP;
}

/*****************************************************************************************************************/
// static u32 get_teid_downlink_session(uint32_t dest_ip) {
  
//   struct next_rule_prog_index_key key = {}, next_key  = {};
//   int err;
//   u32 teid = -1;

//   // while (bpf_map_get_next_key(&m_next_rule_prog_index, &key, &next_key) == 0) {
//   //     key = next_key;
      
//   //     if ((next_key.source_value == INTERFACE_VALUE_CORE) &&
//   //         (next_key.ipv4_address == dest_ip)) {
        
//   //       bpf_debug(
//   //           "Looking for the Key <?, %d, %d>", next_key.source_value, next_key.ipv4_address);

//   //       u32* ret_val = bpf_map_lookup_elem(&m_next_rule_prog_index, &next_key);

//   //       if (ret_val == 0) {
//   //       teid = next_key.teid;  
//   //       bpf_debug(
//   //           "I found TEID %d", teid);
//   //       }
//   //     } 
//   for (;;) {
//     err = bpf_map_get_next_key(&m_next_rule_prog_index, &key, &next_key);
//     if (err)
//       break;

//     u32* ret_val = bpf_map_lookup_elem(&m_next_rule_prog_index, &next_key);

//     // Use key and value here

//     key = next_key;
//   }
  
//   return teid;
// }

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
    struct xdp_md* p_ctx, struct udphdr* udph, u32 dest_ip) {
  void* p_data     = (void*) (long) p_ctx->data;
  void* p_data_end = (void*) (long) p_ctx->data_end;

  u32 dport = htons(udph->dest);

  switch (dport) {
    case GTP_UDP_PORT: {
      struct gtpuhdr* p_gtpuh = (struct gtpuhdr*) (udph + 1);

      // Check if the GTP header extends beyond the data end.
      if ((void*) (p_gtpuh + 1) > p_data_end) {
        bpf_debug("Invalid GTPU packet\n");
        return XDP_DROP;
      }

      bpf_debug("TEID FOUND = %d", p_gtpuh->teid);

      struct ethhdr* p_new_eth = p_data + GTP_ENCAPSULATED_SIZE;

      if ((void*) (p_new_eth + 1) > p_data_end) {
        return XDP_DROP;
      }

      struct iphdr* p_ip_inner = (void*) (p_new_eth + 1);

      if ((void*) (p_ip_inner + 1) > p_data_end) {
        return XDP_DROP;
      }

      return gtp_handle(p_ctx, p_gtpuh, p_ip_inner->saddr);
    }
    default:{
      // The destination IP is the UE IP address (donwlink).
      //u32 teid = get_teid_downlink_session(dest_ip);
        u32 teid = 1107610522;
      //if (teid){
        tail_call_next_prog(p_ctx, teid, INTERFACE_VALUE_CORE, dest_ip);
      //}
      
      return XDP_PASS;
      // return XDP_DROP;
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
    struct xdp_md* p_ctx, struct tcphdr* tcph, u32 src_ip, u32 dest_ip) {
  // void* p_data_end = (void*) (long) p_ctx->data_end;

  bpf_debug("Valid TCP Packet (SRC IP:0x%x, DEST IP:0x%x)\n", src_ip, dest_ip);
  u32 teid = 1107610522;
  tail_call_next_prog(p_ctx, teid, INTERFACE_VALUE_CORE, src_ip);

  return XDP_PASS;
  // return XDP_DROP;
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
    struct xdp_md* p_ctx, struct icmphdr* icmph, u32 dest_ip) { 
    //u32 teid = get_teid_downlink_session(dest_ip);
      u32 teid = 1107610522;
      // if (teid){
        tail_call_next_prog(p_ctx, teid, INTERFACE_VALUE_CORE, dest_ip);
      // }

    return XDP_DROP;
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
  //void* p_data     = (void*) (long) p_ctx->data;
  void* p_data_end = (void*) (long) p_ctx->data_end;

  u32 ip_dest = iph->daddr;

  switch (iph->protocol) {
    case IPPROTO_UDP: {
       bpf_debug("*** This is a UDP packet ***\n");
      struct udphdr* udph = (struct udphdr*) (iph + 1);

      // Check if the UDP header extends beyond the data end.
      if ((void*) (udph + 1) > p_data_end) {
        bpf_debug("Invalid UDP packet\n");
        return XDP_DROP;
      }
      return udp_handle(p_ctx, udph, ip_dest);
    }
      // case IPPROTO_TCP:{
      //   bpf_debug("*** This is a TCP packet ***\n");
      //   struct tcphdr* tcph = (struct tcphdr*)(iph + 1);

      //   // Check if the TCP header extends beyond the data end.
      //   if ((void*)(tcph + 1) > p_data_end) {
      //     bpf_debug("Invalid TCP packet\n");
      //     return XDP_DROP;
      //   }
      //   return tcp_handle(p_ctx, tcph, ip_src, ip_dest);
      // }
    case IPPROTO_ICMP: {
       bpf_debug("*** This is an ICMP packet ***\n");
      struct icmphdr* icmph = (struct icmphdr*) (iph + 1);
      // Check if the ICMP header extends beyond the data end.
      if ((void*) (icmph + 1) > p_data_end) {
        bpf_debug("Invalid ICMP packet\n");
        return XDP_DROP;
      }
      return icmp_handle(p_ctx, icmph, ip_dest);
    }
    default: {
      bpf_debug("Non UDP/TCP/ICMP protocols \n");
      // return XDP_PASS;
      return XDP_DROP;
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
      // return XDP_DROP;
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

// /*****************************************************************************************************************/
// /**
//  * IP SECTION.
//  */

// /**
//  * @brief Handle IPv4 header.
//  *
//  * @param p_ctx The user accessible metadata for xdp packet hook.
//  * @param iph The IP header.
//  * @return u32 The XDP action.
//  */
// static u32 ipv4_handle(struct xdp_md* p_ctx, struct iphdr* iph) {
//   void* p_data_end = (void*) (long) p_ctx->data_end;

//   u32 ip_src  = iph->saddr;
//   u32 ip_dest = iph->daddr;

//   bpf_debug("Valid IPv4 Packet (SRC IP:0x%x, DEST IP:0x%x)\n", ip_src,
//   ip_dest); switch (iph->protocol) {
//     case IPPROTO_UDP: {
//       struct udphdr* udph = (struct udphdr*) (iph + 1);

//       // Check if the UDP header extends beyond the data end.
//       if ((void*) (udph + 1) > p_data_end) {
//         bpf_debug("Invalid UDP packet\n");
//         return XDP_DROP;
//       }
//       return udp_handle(p_ctx, udph, ip_src, ip_dest);
//     }
//     case IPPROTO_TCP:
//     default:
//       bpf_debug("TCP protocol L4\n");
//       return XDP_PASS;
//   }
// }

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
