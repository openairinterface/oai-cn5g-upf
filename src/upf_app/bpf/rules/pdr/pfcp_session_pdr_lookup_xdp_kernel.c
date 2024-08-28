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

/*---------------------------------------------------------------------------------------------------------------*/

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

/*---------------------------------------------------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------------------------------------------------*/
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
/*---------------------------------------------------------------------------------------------------------------*/

SEC("xdp")
int uplink_entry_point(struct xdp_md* p_ctx) {
  bpf_debug("==========< SESSION PDR LOOKUP CONTEXT - UPLINK >==========\n");
  return xdp_stats_record_action(p_ctx, pfcp_pdr_lookup_uplink(p_ctx));
}

SEC("xdp")
int downlink_entry_point(struct xdp_md* p_ctx) {
  bpf_debug("==========< SESSION PDR LOOKUP CONTEXT - DOWNLINK >==========\n");
  return xdp_stats_record_action(p_ctx, pfcp_pdr_lookup_downlink(p_ctx));
}

char _license[] SEC("license") = "GPL";
/*---------------------------------------------------------------------------------------------------------------*/
