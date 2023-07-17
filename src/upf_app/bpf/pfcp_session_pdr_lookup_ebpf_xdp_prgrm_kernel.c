// clang-format off
#include <types.h>
// clang-format on

#include "xdp_stats_kern.h"
#include <bpf_helpers.h>
#include <endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_pdr.h>
#include <protocols/gtpu.h>
#include <protocols/ip.h>
#include <pfcp_session_pdr_lookup_maps.h>
#include <utils/csum.h>
#include <utils/logger.h>
#include <utils/utils.h>
#include <interfaces.h>
#include <pfcp_session_lookup_maps.h>
#include <string.h>  //Needed for memcpy

/*****************************************************************************************************************/
// TODO: Put dummy in test folder.
// /**
//  * WARNING: Redirect require an XDP bpf_prog loaded on the TX device.
//  */
// SEC("xdp_redirect_dummy")
// int xdp_redirect_gtpu(struct xdp_md* p_ctx) {
//   // PASS.
//   bpf_debug("Redirecting packets\n");
//   return XDP_PASS;
// }

/*****************************************************************************************************************/
// /**
//  * @brief Update MAC address
//  *
//  * @param p_ip The IP header which has the destination IP address.
//  * @param [out] p_eth  The eth header with the new mac address.
//  * @return u32 0 (Success), 1 (Fail).
//  */
// static u32 update_dst_mac_address(struct iphdr* p_ip, struct ethhdr* p_eth) {
//   void* p_mac_address;

//   p_mac_address = bpf_map_lookup_elem(&m_arp_table, &p_ip->daddr);

//   if (!p_mac_address) {
//     bpf_debug("MAC Address NOT Found!\n");
//     return XDP_DROP;
//   }

//   __builtin_memcpy(p_eth->h_dest, p_mac_address, sizeof(p_eth->h_dest));
//   return XDP_PASS;
// }

// /*****************************************************************************************************************/
// static u32 create_outer_header_gtpu_ipv4(
//     struct xdp_md* p_ctx, pfcp_far_t_* p_far) {
//   bpf_debug("Create Outer Header GTPU_IPv4\n");
//   bpf_debug("Original Packet: Data/UDP/IP/ETH\n");

//   // Adjust space to the left.
//   bpf_xdp_adjust_head(p_ctx, (int32_t) -GTP_ENCAPSULATED_SIZE);

//   void* p_data_end = (void*) (long) p_ctx->data_end;

//   /*
//   |----------------------------------------------------------------|
//   |----------------------- Update ETH header ----------------------|
//   |----------------------------------------------------------------|
//   */
//   struct ethhdr* p_eth = (void*) (long) p_ctx->data;
//   if ((void*) (p_eth + 1) > p_data_end) {
//     bpf_debug("Invalid pointer\n");
//     return XDP_DROP;
//   }

//   struct ethhdr* p_orig_eth = p_eth + GTP_ENCAPSULATED_SIZE;
//   if ((void*) (p_orig_eth + 1) > p_data_end) {
//     return XDP_DROP;
//   }

//   __builtin_memcpy(p_eth, p_orig_eth, sizeof(*p_eth));

//   /*
//   |----------------------------------------------------------------|
//   |-------------------------- Add IP header -----------------------|
//   |----------------------------------------------------------------|
//   */
//   struct iphdr* p_ip = (void*) (p_eth + 1);
//   if ((void*) (p_ip + 1) > p_data_end) {
//     return XDP_DROP;
//   }

//   struct iphdr* p_inner_ip = (void*) p_ip + GTP_ENCAPSULATED_SIZE;
//   if ((void*) (p_inner_ip + 1) > p_data_end) {
//     return XDP_DROP;
//   }

//   p_ip->version  = 4;
//   p_ip->ihl      = 5;  // No options
//   p_ip->tos      = 0;
//   p_ip->tot_len  = htons(ntohs(p_inner_ip->tot_len) + GTP_ENCAPSULATED_SIZE);
//   p_ip->id       = 0;       // No fragmentation
//   p_ip->frag_off = 0x0040;  // Don't fragment; Fragment offset = 0
//   p_ip->ttl      = 64;
//   p_ip->protocol = IPPROTO_UDP;
//   p_ip->check    = 0;

//   e_reference_point reference = N3_INTERFACE;
//   struct s_interface* map_element    = bpf_map_lookup_elem(&m_upf_interfaces,
//   &reference);

//   if (!map_element) {
//     bpf_debug("N3 Interface NOT Found!\n");
//     return XDP_DROP;
//   }

//   p_ip->saddr = map_element->ipv4_address;
//   bpf_debug(
//       "Map Values: IP:%d, port:%d\n", map_element->ipv4_address,
//       map_element->port);
//   bpf_debug("IP SRC:%d\n", p_ip->saddr);
//   p_ip->daddr =
//       p_far->forwarding_parameters.outer_header_creation.ipv4_address.s_addr;

//   /*
//   |----------------------------------------------------------------|
//   |-------------------------- Add UDP header ----------------------|
//   |----------------------------------------------------------------|
//   */
//   struct udphdr* p_udp = (void*) (p_ip + 1);
//   if ((void*) (p_udp + 1) > p_data_end) {
//     return XDP_DROP;
//   }

//   p_udp->source = htons(GTP_UDP_PORT);
//   p_udp->dest =
//       htons(p_far->forwarding_parameters.outer_header_creation.port_number);
//   p_udp->len = htons(
//       ntohs(p_inner_ip->tot_len) + sizeof(*p_udp) + sizeof(struct gtpuhdr) +
//       sizeof(struct gtpu_extn_pdu_session_container));
//   p_udp->check = 0;

//   /*
//   |----------------------------------------------------------------|
//   |-------------------------- Add GTP header ----------------------|
//   |----------------------------------------------------------------|
//   */
//   bpf_debug(
//       "Destination MAC:%x:%x:%x:", p_eth->h_dest[0], p_eth->h_dest[1],
//       p_eth->h_dest[2]);
//   bpf_debug("%x:%x:%x\n", p_eth->h_dest[3], p_eth->h_dest[4],
//   p_eth->h_dest[5]);

//   void* p_mac_address = bpf_map_lookup_elem(&m_arp_table, &p_ip->daddr);
//   if (!p_mac_address) {
//     bpf_debug("MAC address not found!!\n");
//     return XDP_DROP;
//   }

//   // swap_src_dst_mac(p_data);
//   __builtin_memcpy(p_eth->h_dest, p_mac_address, sizeof(p_eth->h_dest));

//   bpf_debug(
//       "Destination MAC:%x:%x:%x:", p_eth->h_dest[0], p_eth->h_dest[1],
//       p_eth->h_dest[2]);
//   bpf_debug("%x:%x:%x\n", p_eth->h_dest[3], p_eth->h_dest[4],
//   p_eth->h_dest[5]); bpf_debug("Destination IP:%d, \t", p_ip->daddr);
//   bpf_debug(
//       "Port:%d\n",
//       p_far->forwarding_parameters.outer_header_creation.port_number);

//   struct gtpuhdr* p_gtpuh = (void*) (p_udp + 1);
//   if ((void*) (p_gtpuh + 1) > p_data_end) {
//     return XDP_DROP;
//   }

//   u8 flags = GTP_EXT_FLAGS;
//   __builtin_memcpy(p_gtpuh, &flags, sizeof(u8));
//   p_gtpuh->message_type   = GTPU_G_PDU;
//   p_gtpuh->message_length = htons(
//       ntohs(p_inner_ip->tot_len) +
//       sizeof(struct gtpu_extn_pdu_session_container) + 4);
//   p_gtpuh->teid       =
//   p_far->forwarding_parameters.outer_header_creation.teid; p_gtpuh->sequence
//   = GTP_SEQ; p_gtpuh->pdu_number = GTP_PDU_NUMBER; p_gtpuh->next_ext_type =
//   GTP_NEXT_EXT_TYPE;

//   /*
//   |----------------------------------------------------------------|
//   |-------------------- Add GTP extension header ------------------|
//   |----------------------------------------------------------------|
//   */
//   struct gtpu_extn_pdu_session_container* p_gtpu_ext_h = (void*) (p_gtpuh +
//   1); if ((void*) (p_gtpu_ext_h + 1) > p_data_end) {
//     return XDP_DROP;
//   }

//   p_gtpu_ext_h->message_length = GTP_EXT_MSG_LEN;
//   p_gtpu_ext_h->pdu_type       = GTP_EXT_PDU_TYPE;
//   p_gtpu_ext_h->qfi            = GTP_EXT_QFI;
//   p_gtpu_ext_h->next_ext_type  = GTP_EXT_NEXT_EXT_TYPE;

//   /*
//   |----------------------------------------------------------------|
//   |---------------------- Compute L3 CHECKSUM ---------------------|
//   |----------------------------------------------------------------|
//   */
//   __wsum l3sum = pcn_csum_diff(0, 0, (__be32*) p_ip, sizeof(*p_ip), 0);
//   pcn_l3_csum_replace(p_ctx, IP_CSUM_OFFSET, 0, l3sum, 0);

//   bpf_debug("GTP-Encapsulated Packet: Data/UDP/IP/EXT/GTP/UDP/IP/ETH\n");
//   bpf_debug("GTPU header were pushed!\n");
// }

/*****************************************************************************************************************/
// /**
//  * @brief Apply forwarding action rules.
//  *
//  * @param p_gtpuh The GTPU header.
//  * @param p_session The session of this context.
//  * @return u32 XDP action.
//  */

// static u32 pfcp_far_apply(
//     struct xdp_md* p_ctx, pfcp_far_t_* p_far, enum FlowDirection direction) {
//   void* p_data         = (void*) (long) p_ctx->data;
//   void* p_data_end     = (void*) (long) p_ctx->data_end;
//   struct ethhdr* p_eth = p_data;
//   // void *p_mac_address;

//   u8 dest_interface;
//   u16 outer_header_creation;
//   // TODO dupl
//   // TODO nocp
//   // TODO buff

//   if ((void*) (p_eth + 1) > p_data_end) {
//     bpf_debug("Invalid pointer\n");
//     return XDP_DROP;
//   }

//   // Check if it is a forward action.
//   if (!p_far) {
//     bpf_debug("Invalid FAR!\n");
//     return XDP_DROP;
//   }

//   dest_interface =
//       p_far->forwarding_parameters.destination_interface.interface_value;
//   outer_header_creation = p_far->forwarding_parameters.outer_header_creation
//                               .outer_header_creation_description;

//   // TODO: Reorder the if's
//   if (p_far->apply_action.forw) {
//     if (dest_interface == INTERFACE_VALUE_CORE) {
//       // Redirect to data network.
//       bpf_debug("Destination is to INTERFACE_VALUE_CORE\n");
//       // Check Outer header creation - IPv4 or IPv6
//       switch (outer_header_creation) {
//         case OUTER_HEADER_CREATION_UDP_IPV4:
//           bpf_debug("OUTER_HEADER_CREATION_UDP_IPV4\n");
//           struct ethhdr* p_new_eth = p_data + GTP_ENCAPSULATED_SIZE;

//           // Move eth header forward.
//           if ((void*) (p_new_eth + 1) > p_data_end) {
//             return 1;
//           }
//           __builtin_memcpy(p_new_eth, p_eth, sizeof(*p_eth));

//           // Update destination mac address.
//           struct iphdr* p_ip = (void*) (p_new_eth + 1);

//           if ((void*) (p_ip + 1) > p_data_end) {
//             return XDP_DROP;
//           }

//           if (update_dst_mac_address(p_ip, p_new_eth)) {
//             return XDP_DROP;
//           }

//           // Adjust head to the right.
//           bpf_xdp_adjust_head(p_ctx, GTP_ENCAPSULATED_SIZE);

//           return bpf_redirect_map(&m_redirect_interfaces, direction, 0);
//           bpf_debug("OUTER_HEADER_CREATION_UDP_IPV4 REDIRECT FAILED\n");
//           break;
//         case OUTER_HEADER_CREATION_UDP_IPV6:
//           bpf_debug("OUTER_HEADER_CREATION_UDP_IPV6\n");
//           // TODO
//           break;
//         default:
//           bpf_debug(
//               "In destination to CORE - Invalid option: %d\n",
//               outer_header_creation);
//       }
//     } else if (dest_interface == INTERFACE_VALUE_ACCESS) {
//       // Redirect to core network.
//       bpf_debug("Destination is to INTERFACE_VALUE_ACCESS\n");
//       switch (outer_header_creation) {
//         case OUTER_HEADER_CREATION_GTPU_UDP_IPV4:
//           bpf_debug("OUTER_HEADER_CREATION_GTPU_UDP_IPV4\n");
//           create_outer_header_gtpu_ipv4(p_ctx, p_far);
//           return bpf_redirect_map(&m_redirect_interfaces, direction, 0);
//           break;
//         case OUTER_HEADER_CREATION_GTPU_UDP_IPV6:
//           bpf_debug("OUTER_HEADER_CREATION_GTPU_UDP_IPV6\n");
//           break;
//         default:
//           bpf_debug(
//               "In destination to ACCESS - Invalid option: %d\n",
//               outer_header_creation);
//       }
//     }
//   } else {
//     bpf_debug("Forward action unset\n");
//   }
//   return XDP_PASS;
// }

/*****************************************************************************************************************/

/**
 * @brief Match the PDRs attribuites for UL data flow.
 * - The TEID from GTP GPDU with the TEID stored in PDR.
 * - Source IP from IP header with source address stored in PDI.
 * - Interface from PDI with ACCESS interface value.
 *
 * @param p_pdr The PDR to be match with the header.
 * @param p_iph The IP header.
 * @return u8 True if match. False cc.
 */
static u32 pfcp_pdr_match_pdi_access(
    struct xdp_md* p_ctx, pfcp_pdr_t_* p_pdr, struct iphdr* p_iph,
    teid_t_ teid) {
  // if (!p_iph) {
  //   bpf_debug("IP header is NULL!!");
  //   return 0;
  // }

  // clang-format off
  if(p_pdr->outer_header_removal.outer_header_removal_description != OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4
      || p_pdr->pdi.source_interface.interface_value != INTERFACE_VALUE_ACCESS
      || p_pdr->pdi.fteid.teid != teid
      || p_pdr->pdi.ue_ip_address.ipv4_address != p_iph->saddr
    ){
        bpf_debug("Not match:");
        bpf_debug("OHRD: %d", OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4 );
        bpf_debug("OHRD: %d", p_pdr->outer_header_removal.outer_header_removal_description);
        bpf_debug("Interface: %d", INTERFACE_VALUE_ACCESS);
        bpf_debug("Interface: %d", p_pdr->pdi.source_interface.interface_value);
        bpf_debug("TEID: %d", teid);
        bpf_debug("TEID: %d", p_pdr->pdi.fteid.teid);
        // bpf_debug("IPv4: %d", p_iph->saddr);
        bpf_debug("IPv4: %d", p_pdr->pdi.ue_ip_address.ipv4_address);
        return XDP_DROP;
    }
  // clang-format on

  // All the attributes were matched.
  bpf_debug("All atrributes were matched!!");
  return XDP_PASS;
}

/*****************************************************************************************************************/
/**
 * @brief Match the PDRs attribuites for DL data flow.
 * - Destination IP from IP header with source address stored in PDI.
 * - Interface from PDI with CORE interface value.
 *
 * @param p_pdr The PDR to be match with the header.
 * @param p_iph The IP header.
 * @return u8 True if match. False cc.
 */
static u32 pfcp_pdr_match_pdi_downlink(
    pfcp_pdr_t_* p_pdr, struct iphdr* p_iph) {
  // if (!p_iph) {
  //   bpf_debug("IP header is NULL!\n");
  //   return 0;
  // }

  // clang-format off
  if(p_pdr->outer_header_removal.outer_header_removal_description != OUTER_HEADER_REMOVAL_UDP_IPV4
      || p_pdr->pdi.source_interface.interface_value != INTERFACE_VALUE_CORE
      // || p_pdr->pdi.fteid.teid != teid
      // FIXME
      || p_pdr->pdi.ue_ip_address.ipv4_address != p_iph->daddr
    ){
        bpf_debug("Not match:\n");
        bpf_debug("OHRD: %d\n", OUTER_HEADER_REMOVAL_UDP_IPV4 );
        bpf_debug("OHRD: %d\n", p_pdr->outer_header_removal.outer_header_removal_description);
        bpf_debug("Interface: %d\n", INTERFACE_VALUE_CORE);
        bpf_debug("Interface: %d\n", p_pdr->pdi.source_interface.interface_value);
        // bpf_debug("TEID: %d\n", teid);
        // bpf_debug("TEID: %d\n", p_pdr->pdi.fteid.teid);
        bpf_debug("IPv4: %d\n", p_iph->daddr);
        bpf_debug("IPv4: %d\n", p_pdr->pdi.ue_ip_address.ipv4_address);
        return XDP_DROP;
    }
  // clang-format on

  // All the attributes were matched.
  bpf_debug("All atrributes were matched!\n");
  return XDP_PASS;
}

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
    bpf_debug("BPF tail call was not executed!\n");
  }
  bpf_debug("BPF tail call was not executed!\n");
  bpf_debug("One reason could be:\n");
  bpf_debug(
      "1. Key values not matching hash key for map m_next_rule_prog!\n \
             \t\t\t\t\t\t You have to compare the keys\n \
             \t\t\t\t\t\t 2. Endianess problem!\n \
             \t\t\t\t\t\t Map and Key values are saved in different endianess!\n\
             \t\t\t\t\t\t Map Hash Key and Key not matching\n");

  return 0;
}

/*****************************************************************************************************************/
/**
 * @brief Lookup all PDRs based on teid.
 * After that, for each PDR, check the its attribuites with match with access
 * way.
 * - The TEID from GTP GPDU with the TEID stored in PDR.
 * - Source IP from IP header with source address stored in PDI.
 * - Interface from PDI with ACCESS or CORE interface (it depends on if it is UL
 * or DL). After match all field, get the session id in the found PDR.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param p_gtpuh
 * @return u32
 */
static u32 pfcp_pdr_lookup_uplink(struct xdp_md* p_ctx) {
  u32 i            = 0;
  void* p_data     = (void*) (long) p_ctx->data;
  void* p_data_end = (void*) (long) p_ctx->data_end;

  u64 offset =
      sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

  if (p_data + offset + sizeof(struct gtpuhdr) > p_data_end) {
    bpf_debug("Invalid GTP packet!");
    return XDP_DROP;  // XDP_PASS;
  }

  // Get GTP base address.
  struct gtpuhdr* p_gtpuh = p_data + offset;

  teid_t_ teid = htons(p_gtpuh->teid);
  bpf_debug("GTP GPDU TEID %d with IPv4 payload received\n", teid);

  pfcp_pdr_t_* p_pdr = bpf_map_lookup_elem(&m_teid_pdr, &teid);

  if (!p_pdr) {
    bpf_debug("Error - unsync teid->pdrs map.\n");
    return XDP_DROP;
  }

  // We have already assumed that the packet is a GPDU.
  struct iphdr* p_iph =
      (struct iphdr*) ((u8*) p_gtpuh + GTPV1U_MSG_HEADER_MIN_SIZE);

  // Check if the IPv4 header extends beyond the data end.
  if ((void*) (p_iph + 1) > p_data_end) {
    bpf_debug("Invalid IPv4 Packet\n");
    return XDP_DROP;
  }

  // For each PDR, check parameters.
  pfcp_pdr_match_pdi_access(p_ctx, &p_pdr[i], p_iph, teid);
  bpf_debug(
      "PDR associated with teid %d found! PDR id is %d\n", teid,
      p_pdr->pdr_id.rule_id);

  // Lets apply the forwarding actions rule.
  pfcp_far_t_* p_far = bpf_map_lookup_elem(&m_fars, &p_pdr->far_id.far_id);
  if (p_far) {
    // return pfcp_far_apply(p_ctx, p_far, UPLINK);

    // Jump to session context.
    tail_call_next_prog(p_ctx, teid, INTERFACE_VALUE_ACCESS, p_iph->saddr);
    bpf_debug("BPF tail call was not executed! teid %d\n", teid);
  }

  bpf_debug("FAR was NOT Found\n");
  return XDP_DROP;  // XDP_PASS;
}

/*****************************************************************************************************************/
/**
 * @brief Lookup all PDRs based on IP.
 * After that, for each PDR, check the its attribuites with match with access
 * way.
 * - The TEID from GTP GPDU with the TEID stored in PDR.
 * - Source IP from IP header with source address stored in PDI.
 * - Interface from PDI with ACCESS or CORE interface (it depends on if it is UL
 * or DL). After match all field, get the session id in the found PDR.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param p_gtpuh
 * @return u32
 */
static u32 pfcp_pdr_lookup_downlink(struct xdp_md* p_ctx) {
  u32 i            = 0;
  void* p_data     = (void*) (long) p_ctx->data;
  void* p_data_end = (void*) (long) p_ctx->data_end;

  if (p_data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct udphdr) >
      p_data_end) {
    bpf_debug("Invalid GTP packet!\n");
    return XDP_DROP;  // XDP_PASS;
  }

  // Get GTP base address.
  struct iphdr* p_iph = p_data + sizeof(struct ethhdr);

  // Check if the IPv4 header extends beyond the data end.
  if ((void*) (p_iph + 1) > p_data_end) {
    bpf_debug("Invalid IPv4 Packet\n");
    return XDP_DROP;
  }

  u32 dest_ip = p_iph->daddr;
  bpf_debug("Destination IP %d in IPv4 payload received\n", dest_ip);

  pfcp_pdr_t_* p_pdr = bpf_map_lookup_elem(&m_ueip_pdr, &dest_ip);

  if (!p_pdr) {
    bpf_debug("Error - unsync teid->pdrs map.\n");
    return XDP_DROP;
  }

  // For each PDR, check parameters.
  pfcp_pdr_match_pdi_downlink(&p_pdr[i], p_iph);

  // Lets apply the forwarding actions rule.
  pfcp_far_t_* p_far = bpf_map_lookup_elem(&m_fars, &p_pdr->far_id.far_id);

  if (p_far) {
    bpf_debug(
        "PDR associated with UP IP %d found! PDR id:%d and FAR id:%d\n",
        htonl(p_iph->daddr), p_pdr->pdr_id.rule_id, p_pdr->far_id.far_id);
    // return pfcp_far_apply(p_ctx, p_far, DOWNLINK);

    // Jump to session context.
    tail_call_next_prog(p_ctx, 0, INTERFACE_VALUE_CORE, p_iph->saddr);
    bpf_debug("BPF tail call was not executed!\n");
  }

  bpf_debug("FAR was NOT Found\n");
  return XDP_DROP;  // XDP_PASS;
}
/*****************************************************************************************************************/

SEC("xdp_uplink_entry_point")
int uplink_entry_point(struct xdp_md* p_ctx) {
  bpf_debug("==========< SESSION PDR LOOKUP CONTEXT - UPLINK >==========\n");
  return xdp_stats_record_action(p_ctx, pfcp_pdr_lookup_uplink(p_ctx));
}

SEC("xdp_downlink_entry_point")
int downlink_entry_point(struct xdp_md* p_ctx) {
  bpf_debug("==========< SESSION PDR LOOKUP CONTEXT - DOWNLINK >==========\n");
  return xdp_stats_record_action(p_ctx, pfcp_pdr_lookup_downlink(p_ctx));
}

char _license[] SEC("license") = "GPL";
/*****************************************************************************************************************/
