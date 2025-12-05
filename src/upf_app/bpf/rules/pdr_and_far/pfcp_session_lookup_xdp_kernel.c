#define KBUILD_MODNAME pfcp_session_lookup_xdp_kernel

#include <types.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <endian.h>
//#include <lib/crc16.h>
#include <utils/csum.h>

#include <protocols/ip.h>
#include <protocols/gtpu.h>
#include <protocols/udp.h>
#include <protocols/tcp.h>
#include <protocols/eth.h>

#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_pdr.h>

#include <ie/group_ie/pdi.h>

#include <pfcp_session_lookup_maps.h>
#include <far_maps.h>
#include <interfaces.h>
#include <sdf_filter.h>

#include <utils/logger.h>
#include <utils/utils.h>
#include "framed_routing_bpf.h"
#include <utils/types.h>
#include <mac_pdu_session_key.h>
#include <pfcp_session_eth_pdu.h>
#include <framed_routing_bpf.h>

#include "xdp_stats_kern.h"
#include <linux/bpf.h>

#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

#include "bpf_endian.h"

#include <string.h>  //Needed for memcpy

#ifdef KERNEL_SPACE
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif
#include <stdio.h>

/* Defines xdp_stats_map */
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"
#include <linux/types.h>
#include <stdbool.h>
struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

static u32 upf_n3_ip = 0;
static u32 upf_n6_ip = 0;

static u8 next_hop_n3_mac_address[6] = {0};
// static u8 next_hop_n6_mac_address[6] = {0};

static bool cached_n3 = false;
// static bool cached_n6 = false;

const volatile struct pdr_lookup_config config = {
    .ignore_qfi_for_uplink = true,  // Default: enable QFI ignore mode
};

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline u32 match_sdf_filter_ipv4(
    const struct packet_filter* filter, const struct sdf_filtr* sdf) {
  u8 packet_protocol  = filter->protocol;
  u16 packet_src_port = filter->src_port;
  u16 packet_dst_port = filter->dst_port;
  u32 packet_src_ip   = bpf_htonl(filter->src_ip);
  u32 packet_dst_ip   = bpf_htonl(filter->dst_ip);

  u32 sdf_src_ip = bpf_htonl(sdf->src_addr.ip);
  u32 sdf_dst_ip = bpf_htonl(sdf->dst_addr.ip);

  /*
  * TODO:
  * Currently we are only working with Ipv4 packets but the struct are
  designed
  * to support both Ipv4 and Ipv6
  * For now we only treat IPv4 packets over the datapath/PFCP
    }
 */

  u32 sdf_src_mask =
      bpf_htonl((u32) (sdf->src_addr.mask >> 96));  // get the top 32 bits of
                                                    // 128-bits mask
  u32 sdf_dst_mask =
      bpf_htonl((u32) (sdf->dst_addr.mask >> 96));  // get the top 32 bits of
                                                    // 128-bits mask

  bpf_debug(" Standard IANA-assigned IP protocol numbers:");

  bpf_debug("{ip, 0}, {icmp, 1}, {tcp, 6}, {udp, 17}, {icmp6, 58}");

  bpf_debug(
      "( sdf_protocol, packet_protocol ) : ( %u, %u )", sdf->protocol,
      packet_protocol);

  bpf_debug(
      "( sdf_saddr/mask, packet_saddr ) : ( %pI4/%pI4, %pI4 )", &sdf_src_ip,
      &sdf_dst_mask, &packet_src_ip);

  bpf_debug(
      "( sdf_daddr/mask, packet_daddr ) : ( %pI4/%pI4, %pI4 )", &sdf_dst_ip,
      &sdf_dst_mask, &packet_dst_ip);

  bpf_debug(
      "( (sdf_sport_lower, sdf_sport_upper), packet_sport ) : ( (%u, %u), %u "
      ")",
      sdf->src_port.lower_bound, sdf->src_port.upper_bound, packet_src_port);

  bpf_debug(
      "( (sdf_dport_lower, sdf_dport_upper), packet_dport ) : ( (%u, %u), %u "
      ")",
      sdf->dst_port.lower_bound, sdf->dst_port.upper_bound, packet_dst_port);

  /*
   * TODO:
   * Check if an enum is really needed to redefine protocol:
   * switch (ip_protocol) {
         case IPPROTO_ICMP:
           return 0;
         case IPPROTO_TCP:
           return 2;
         case IPPROTO_UDP:
           return 3;
         default:
           return 1;
     }
  */
  if (((sdf->protocol == 0) || (packet_protocol == sdf->protocol)) &&
      ((packet_src_ip & sdf_src_mask) == sdf_src_ip) &&
      ((packet_dst_ip & sdf_dst_mask) == sdf_dst_ip) &&
      ((packet_src_port >= sdf->src_port.lower_bound) &&
       (packet_src_port <= sdf->src_port.upper_bound)) &&
      ((packet_dst_port >= sdf->dst_port.lower_bound) &&
       (packet_dst_port <= sdf->dst_port.upper_bound))) {
    bpf_debug("Packet filter is matching SDF");
    return 1;
  }
  bpf_debug("Packet filter and SDF are not matching");
  return 0;
}

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline u32
create_outer_header_gtpu_ipv4(struct xdp_md* ctx, pfcp_far_t_* p_far, u8 qfi) {
  // Adjust space to the left.
  if (bpf_xdp_adjust_head(ctx, (int32_t) -GTP_ENCAPSULATED_SIZE)) {
    return DROP;
  }

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  // Retrieve the N3 Interface IP address:
  e_reference_point n3_key = N3_INTERFACE;

  if (!cached_n3) {
    struct s_interface* map_element =
        bpf_map_lookup_elem(&m_upf_interfaces, &n3_key);

    if (!map_element) {
      bpf_debug("N3 interface is missing in UPF map, Drop the packet");
      return FAILURE;
    }

    upf_n3_ip = map_element->ipv4_address;
    cached_n3 = true;
  }

  struct s_arp_mapping* map_entry = {0};
  map_entry = bpf_map_lookup_elem(&m_arp_table, &upf_n3_ip);

  if (!map_entry) {
    bpf_debug("N3's Next Hop MAC address not found! Drop the packet");
    return FAILURE;
  }

  memcpy(
      next_hop_n3_mac_address, map_entry->mac_address,
      sizeof(next_hop_n3_mac_address));

  /*
  |----------------------------------------------------------------|
  |----------------------- Update ETH header ----------------------|
  |----------------------------------------------------------------|
  */
  struct ethhdr* ethh = data;
  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return DROP;
  }

  struct ethhdr* ethh_orig = data + GTP_ENCAPSULATED_SIZE;

  if ((void*) (ethh_orig + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet copy header");
    return DROP;
  }
  __builtin_memcpy(ethh, ethh_orig, sizeof(*ethh));

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add IP header -----------------------|
  |----------------------------------------------------------------|
  */
  struct iphdr* iph = (void*) (ethh + 1);
  if ((void*) (iph + 1) > data_end) {
    return DROP;
  }

  struct iphdr* p_inner_ip = (void*) iph + GTP_ENCAPSULATED_SIZE;
  if ((void*) (p_inner_ip + 1) > data_end) {
    return DROP;
  }

  iph->version = 4;
  iph->ihl     = 5;  // No options
  iph->tos     = 0;
  iph->tot_len =
      bpf_htons(bpf_ntohs(p_inner_ip->tot_len) + GTP_ENCAPSULATED_SIZE);
  iph->id       = 0;       // No fragmentation
  iph->frag_off = 0x0040;  // Don't fragment; Fragment offset = 0
  iph->ttl      = 64;
  iph->protocol = IPPROTO_UDP;
  iph->check    = 0;
  iph->saddr    = upf_n3_ip;
  iph->daddr =
      p_far->forwarding_parameters.outer_header_creation.ipv4_address.s_addr;

  bpf_debug(
      "outer IP header ( ip_saddr, ip_daddr ) : ( %pI4, %pI4 )", &iph->saddr,
      &iph->daddr);

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add UDP header ----------------------|
  |----------------------------------------------------------------|
  */
  struct udphdr* udph = (void*) (iph + 1);
  if ((void*) (udph + 1) > data_end) {
    return DROP;
  }

  udph->source = bpf_htons(GTP_UDP_PORT);
  udph->dest   = bpf_htons(GTP_UDP_PORT);
  // bpf_htons(p_far->forwarding_parameters.outer_header_creation.port_number);
  udph->len = bpf_htons(
      bpf_ntohs(p_inner_ip->tot_len) + sizeof(*udph) + sizeof(struct gtpuhdr) +
      sizeof(struct gtpu_extn_pdu_session_container));
  udph->check = 0;

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add GTP header ----------------------|
  |----------------------------------------------------------------|
  */
  // Update destination mac address
  memcpy(ethh->h_dest, next_hop_n3_mac_address, sizeof(ethh->h_dest));

  bpf_debug(
      "Destination MAC:%x:%x:%x:", ethh->h_dest[0], ethh->h_dest[1],
      ethh->h_dest[2]);
  bpf_debug("%x:%x:%x", ethh->h_dest[3], ethh->h_dest[4], ethh->h_dest[5]);

  struct gtpuhdr* p_gtpuh = (void*) (udph + 1);
  if ((void*) (p_gtpuh + 1) > data_end) {
    return DROP;
  }

  u8 flags = GTP_EXT_FLAGS;
  __builtin_memcpy(p_gtpuh, &flags, sizeof(u8));
  p_gtpuh->message_type   = GTPU_G_PDU;
  p_gtpuh->message_length = bpf_htons(
      bpf_ntohs(p_inner_ip->tot_len) +
      sizeof(struct gtpu_extn_pdu_session_container) + 4);
  p_gtpuh->teid =
      bpf_htonl(p_far->forwarding_parameters.outer_header_creation.teid);
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
    return DROP;
  }

  p_gtpu_ext_h->message_length = GTP_EXT_MSG_LEN;
  p_gtpu_ext_h->pdu_type       = GTP_EXT_PDU_TYPE;
  p_gtpu_ext_h->qfi            = qfi;  // GTP_DEFAULT_QFI;
  p_gtpu_ext_h->next_ext_type  = GTP_EXT_NEXT_EXT_TYPE;

  /*
  |----------------------------------------------------------------|
  |---------------------- Compute L3 CHECKSUM ---------------------|
  |----------------------------------------------------------------|
  */
  __wsum l3sum = pcn_csum_diff(0, 0, (__be32*) iph, sizeof(*iph), 0);
  int ret      = pcn_l3_csum_replace(ctx, IP_CSUM_OFFSET, 0, l3sum, 0);

  if (ret) {
    bpf_debug("Error: Invalid Checksum Calculation %d\n", ret);
  }

  bpf_debug(
      "Pushes the GTP-Encapsulated packet: Data/UDP/IP/EXT/GTP/UDP/IP/ETH");
  return SUCCESS;
}

//--------------------------------------------------------------------------------------

static __always_inline u32
remove_outer_header_gtpu_ipv4(struct xdp_md* ctx, pfcp_far_t_* far) {
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  struct ethhdr* ethh = data;
  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return DROP;
  }

  if (!far->apply_action.forw) {
    bpf_debug("Forward Action Is NOT set");
    return FAILURE;
  }

  bpf_debug("GTP Header Removal in Progress");

  struct ethhdr* new_ethh = data + GTP_ENCAPSULATED_SIZE;
  if ((void*) new_ethh + sizeof(*new_ethh) > data_end) {
    bpf_debug("Error: Invalid Ethernet copy header");
    return DROP;
  }
  __builtin_memcpy(new_ethh, ethh, sizeof(*ethh));

  e_reference_point n6_key = N6_INTERFACE;

  // if (!cached_n6) {
  struct s_interface* map_element =
      bpf_map_lookup_elem(&m_upf_interfaces, &n6_key);

  if (!map_element) {
    bpf_debug("N6 interface is missing in UPF map. Drop the packet");
    return FAILURE;
  }

  upf_n6_ip = map_element->ipv4_address;

  struct s_arp_mapping* map_entry = {0};
  map_entry = bpf_map_lookup_elem(&m_arp_table, &upf_n6_ip);

  if (!map_entry) {
    bpf_debug("N6's Next Hop MAC address not found. Drop the packet");
    return FAILURE;
  }

  memcpy(new_ethh->h_dest, map_entry->mac_address, sizeof(new_ethh->h_dest));

  bpf_debug(
      "Destination MAC  %x:%x:%x:", new_ethh->h_dest[0], new_ethh->h_dest[1],
      new_ethh->h_dest[2]);
  bpf_debug(
      " %x:%x:%x", new_ethh->h_dest[3], new_ethh->h_dest[4],
      new_ethh->h_dest[5]);

  // Adjust head to the right.
  if (bpf_xdp_adjust_head(ctx, GTP_ENCAPSULATED_SIZE)) {
    bpf_debug("Error: Adjusting packet head failed");
    return DROP;
  }

  bpf_debug("Outer header has been removed");

  // return bpf_redirect_map(&m_redirect_interfaces, UPLINK, 0);
  return SUCCESS;
  // bpf_debug("OUTER_HEADER_CREATION_UDP_IPV4 REDIRECT FAILED");
}

//--------------------------------------------------------------------------------------
static __always_inline struct session_id* pfcp_session_lookup_over_n3(
    void* data, void* data_end, struct ethhdr* ethh, u32* ue_ip_out,
    u8* qfi_out) {
  u16 l3_protocol = bpf_htons(ethh->h_proto);
  bpf_debug("Debug: l3_protocol:0x%x", l3_protocol);

  switch (l3_protocol) {
    case ETH_P_IP: {
      struct iphdr* iph = (struct iphdr*) (ethh + 1);
      if ((void*) (iph + 1) > data_end) {
        bpf_debug("Error: Invalid IPv4 header");
        return NULL;
      }

      struct udphdr* udph = (struct udphdr*) (iph + 1);
      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Error: Invalid UDP header");
        return NULL;
      }

      if (bpf_htons(udph->dest) != GTP_UDP_PORT) {
        bpf_debug("Error: Invalid GTP Port");
        return NULL;
      }

      bpf_debug("Identified GTP Traffic");

      struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);
      if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
        bpf_debug("Error: Invalid GTP-U header");
        return NULL;
      }

      if (gtpuh->message_type != GTPU_G_PDU) {
        bpf_debug(
            "Message type 0x%x is not GTPU GPDU(0x%x)\n", gtpuh->message_type,
            GTPU_G_PDU);
        return NULL;
      }

      struct gtpu_extn_pdu_session_container* ext_gtpuh =
          (struct gtpu_extn_pdu_session_container*) (gtpuh + 1);

      if ((void*) (ext_gtpuh + 1) > data_end) {
        bpf_debug("Error: Invalid GTPU Extension header");
        return NULL;
      }

      struct iphdr* iph_inner = (struct iphdr*) (ext_gtpuh + 1);
      if ((void*) (iph_inner + 1) > data_end) {
        bpf_debug("Error: Invalid Inner IP header");
        return NULL;
      }

      *ue_ip_out = bpf_htonl(iph_inner->saddr);
      *qfi_out   = ext_gtpuh->qfi;
      return bpf_map_lookup_elem(&m_session_mapping, ue_ip_out);
    }
    case ETH_P_IPV6: {
      bpf_debug("Error: Unsupported IPv6 packet");
      return NULL;
    }
    case ETH_P_ARP: {
      bpf_debug("Info: This is an ARP packet");
      return NULL;
    }
    case ETH_P_8021Q: {
      bpf_debug("Info: This is a VLAN packet");
      return NULL;
    }
    case ETH_P_8021AD: {
      bpf_debug("This is a VLAN packet");
      return NULL;
    }

    default: {
      bpf_debug("Error: Unknown L3 packet");
      return NULL;
    }
  }
}

//--------------------------------------------------------------------------------------

/*
 * Helper function to match packet against SDF filter
 * Extracts packet 5-tuple and calls match_sdf_filter_ipv4
 */
static __always_inline bool packet_filter_is_matching_sdf(
    struct iphdr* iph, void* l4_hdr, const struct sdf_filtr* sdf,
    void* data_end) {
  struct packet_filter filter = {0};

  // Extract IP addresses and protocol
  filter.src_ip   = bpf_htonl(iph->saddr);
  filter.dst_ip   = bpf_htonl(iph->daddr);
  filter.protocol = iph->protocol;

  // Extract port numbers based on protocol
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr* tcph = (struct tcphdr*) l4_hdr;
    if ((void*) (tcph + 1) > data_end) {
      return false;
    }
    filter.src_port = bpf_htons(tcph->source);
    filter.dst_port = bpf_htons(tcph->dest);
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr* udph = (struct udphdr*) l4_hdr;
    if ((void*) (udph + 1) > data_end) {
      return false;
    }
    filter.src_port = bpf_htons(udph->source);
    filter.dst_port = bpf_htons(udph->dest);
  } else {
    // For other protocols (ICMP, etc.), ports are not applicable
    filter.src_port = 0;
    filter.dst_port = 0;
  }

  return match_sdf_filter_ipv4(&filter, sdf);
}

//--------------------------------------------------------------------------------------

/*
 * 3GPP TS 29.244 Section 5.2.1A (Packet Detection Rule Handling):
 * Multiple PDRs may match a packet. When multiple PDRs match, the PDR with
 * the lowest Precedence value shall be selected.
 *
 * 3GPP TS 29.244 Section 8.2.X
 * For uplink packets, the PDI may contain:
 * - UE IP address(es) (mandatory for N3 interface)
 * - F-TEID (GTP-U tunnel information)
 * - QFI(s) (QoS Flow Identifier)
 * - SDF Filter(s) (optional, for fine-grained packet filtering)
 *
 * IMPORTANT: If ignore_qfi_for_uplink is true, UPF will ignore QFI and classify
 * traffic using only TEID + SDF filters. This is standards-compliant, but means
 * all traffic on the TEID gets the same radio QoS; UPF can still enforce
 * different QoS for core network and charging/reporting.
 */
static __always_inline pfcp_pdr_t_* pfcp_session_s_lookup_precedence_over_n3(
    u64 seid, u32 packet_teid, u32 packet_ue_ip, u8 packet_qfi,
    struct iphdr* iph, void* l4_hdr, void* data_end) {
  bpf_debug(
      "Looking up PDRs for SEID=%llu, packet TEID=%u, QFI=%u", seid,
      packet_teid, packet_qfi);

  pfcp_pdr_t_(*pdrs)[MAX_PDRS_PER_SESSION] =
      bpf_map_lookup_elem(&m_session_pdrs, &seid);

  if (!pdrs) {
    bpf_debug("No PDRs found in m_session_pdrs map for SEID: %llu", seid);
    return NULL;
  }

  bpf_debug("Found PDR array for SEID=%llu, checking each PDR...", seid);

  pfcp_pdr_t_* best_match = NULL;
  u32 best_precedence     = 0xFFFFFFFF;

#pragma clang loop unroll(full)
  for (int i = 0; i < MAX_PDRS_PER_SESSION; i++) {
    if (i >= max_pdrs_per_pdu_session) break;
    pfcp_pdr_t_* pdr_high_prec = &(*pdrs)[i];
    pdi_t_ pdi                 = pdr_high_prec->pdi;
    u32 ipaddr                 = bpf_htonl(pdi.ue_ip_address.ipv4_address);
    u32 precedence             = pdr_high_prec->precedence.precedence;

    if ((ipaddr == packet_ue_ip) &&
        (bpf_htonl(pdi.source_interface.interface_value) ==
         INTERFACE_VALUE_ACCESS)) {
      bpf_debug(
          "Precedence=%u, TEID=%d, QFI=%u", precedence, pdi.fteid.teid,
          pdi.qfi.qfi);
      bpf_debug(
          "( packet_ue_ip,  pdi.ue_ip_address ) : ( %pI4, %pI4 )",
          &packet_ue_ip, &ipaddr);
      bpf_debug(
          "( packet_teid,   pdi.fteid.teid    ) : ( %d  , %d )", packet_teid,
          pdi.fteid.teid);
      bpf_debug(
          "( packet_qfi,    pdi.qfi.qfi       ) : ( %u  , %u )", packet_qfi,
          pdi.qfi.qfi);
      bool match = false;
      if (config.ignore_qfi_for_uplink) {
        match = (packet_teid == pdi.fteid.teid);
      } else {
        match =
            ((packet_teid == pdi.fteid.teid) && (packet_qfi == pdi.qfi.qfi));
      }

      if (match) {
        // Check if this PDR has SDF filters
        // When config.ignore_qfi_for_uplink is true and QFIs don't match, skip
        // SDF filter check (the packet's QFI is what matters for SDF filter
        // lookup)
        struct session_qfi sdf_key = {
            .seid = seid,
            .qfi  = config.ignore_qfi_for_uplink ? packet_qfi : pdi.qfi.qfi,
        };

        struct sdf_filtr* sdf = bpf_map_lookup_elem(&m_sdf_filter, &sdf_key);

        if (sdf) {
          // SDF filter exists - must match packet
          bpf_debug(
              "SDF key ( seid, qfi ): ( %llu, %u )", sdf_key.seid, sdf_key.qfi);

          if (packet_filter_is_matching_sdf(iph, l4_hdr, sdf, data_end)) {
            bpf_debug(
                "SDF Match! PDR %u (Precedence: %u) is a candidate",
                pdr_high_prec->pdr_id.rule_id, precedence);
            if (precedence < best_precedence) {
              best_match      = pdr_high_prec;
              best_precedence = precedence;
              bpf_debug(
                  "New best match: PDR %u (Precedence: %u)",
                  pdr_high_prec->pdr_id.rule_id, precedence);
            }
          } else {
            bpf_debug(
                "SDF filter did NOT match for PDR %u, continuing to next PDR",
                pdr_high_prec->pdr_id.rule_id);
          }
        } else {
          // No SDF filter - TEID (or TEID+QFI) match is sufficient
          bpf_debug(
              "No SDF filter for PDR %u - TEID%s match is sufficient",
              pdr_high_prec->pdr_id.rule_id,
              config.ignore_qfi_for_uplink ? "" : "+QFI");
          if (precedence < best_precedence) {
            best_match      = pdr_high_prec;
            best_precedence = precedence;
            bpf_debug(
                "New best match: PDR %u (Precedence: %u)",
                pdr_high_prec->pdr_id.rule_id, precedence);
          }
        }
      } else {
        bpf_debug(
            "PDR %u did NOT match (TEID%s mismatch), continuing...",
            pdr_high_prec->pdr_id.rule_id,
            config.ignore_qfi_for_uplink ? "" : " or QFI");
      }
    }
  }

  if (best_match) {
    bpf_debug(
        "Returning best match: PDR %u (Precedence: %u)",
        best_match->pdr_id.rule_id, best_match->precedence.precedence);
  }

  return best_match;
}

//--------------------------------------------------------------------------------------
static __always_inline u32 apply_rules_matching_pdr_over_n3(
    struct xdp_md* ctx, struct ethhdr* ethh,
    struct pdrs_per_session key_rules_matching_pdr) {
  struct rules_match_pdr* rules = {0};
  u64 seid                      = key_rules_matching_pdr.seid;

  rules = bpf_map_lookup_elem(&m_rules_match_pdr, &key_rules_matching_pdr);

  if (!rules) {
    bpf_debug("No rule was found for the PDR");
    return FAILURE;
  }

  pfcp_far_t_* far = &rules->far;

  if (far) {
    bpf_debug("FAR ID = %d", far->far_id.far_id);
    int ret = remove_outer_header_gtpu_ipv4(ctx, far);
    switch (ret) {
      case SUCCESS: {
        bpf_debug("Redirecting packet to DN");
        return REDIRECT;
      }
      case FAILURE: {
        bpf_debug("Something went wrong");
        return FAILURE;
      }
      case DROP: {
        bpf_debug(
            "DROP: remove_outer_header_gtpu_ipv4() fails for session %llu. "
            "Drop packet",
            seid);
        return DROP;
      }
      default: {
        bpf_debug(
            "Unknown return code from remove_outer_header_gtpu_ipv4() fails "
            "for session %llu",
            seid);
        return FAILURE;
      }
    }
  }

  bpf_debug("Forwarding Action (FAR) not found for session %llu", seid);
  return FAILURE;
}

//--------------------------------------------------------------------------------------
static __always_inline u32 apply_rules_matching_pdr_over_n6(
    struct xdp_md* ctx, struct ethhdr* ethh,
    struct pdrs_per_session key_rules_matching_pdr, u8 qfi) {
  struct rules_match_pdr* rules = {0};
  u64 seid                      = key_rules_matching_pdr.seid;

  rules = bpf_map_lookup_elem(&m_rules_match_pdr, &key_rules_matching_pdr);

  if (!rules) {
    bpf_debug("No rule was found for the PDR");
    return FAILURE;
  }

  pfcp_far_t_* far = &rules->far;
  if (far) {
    bpf_debug("FAR ID = %d", far->far_id.far_id);

    int ret = create_outer_header_gtpu_ipv4(ctx, far, qfi);
    switch (ret) {
      case SUCCESS: {
        u32* qos_enabling = bpf_map_lookup_elem(&m_qos_enabling, &seid);
        if (!qos_enabling) {
          bpf_debug("QoS Enforcement is Disabled for PDU session %llu", seid);
          // return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
          return REDIRECT;
        } else {
          pfcp_qer_t_* qer = &rules->qer;
          if (qer->gate_status.dl_gate == 0) {
            return PASS;
          } else {
            bpf_debug("Gate is close for Session %llu. Drop all traffic", seid);
            return FAILURE;
          }
        }
      }
      case DROP: {
        bpf_debug(
            "DROP: create_outer_header_gtpu_ipv4() fails for session %llu. "
            "Drop packet",
            seid);
        return DROP;
      }
      case FAILURE: {
        bpf_debug(
            "FAILURE: create_outer_header_gtpu_ipv4() fails for session %llu. "
            "Drop packet",
            seid);
        return DROP;
      }
      default: {
        bpf_debug(
            "Unknown return code from create_outer_header_gtpu_ipv4() fails "
            "for session %llu",
            seid);
        return FAILURE;
      }
    }
  }

  bpf_debug("Forwarding Action (FAR) not found for session %llu", seid);

  return FAILURE;
}

//--------------------------------------------------------------------------------------
static __always_inline struct session_id* pfcp_session_lookup_over_n6(
    void* data, void* data_end, struct ethhdr* ethh, u32* ue_ip_out,
    struct packet_filter* packet_filter_out) {
  u16 l3_protocol = bpf_htons(ethh->h_proto);
  bpf_debug("Debug: l3_protocol:0x%x", l3_protocol);

  switch (l3_protocol) {
    case ETH_P_IP: {
      struct iphdr* iph = (struct iphdr*) (ethh + 1);
      if ((void*) (iph + 1) > data_end) {
        bpf_debug("Error: Invalid IPv4 header");
        return NULL;
      }

      *ue_ip_out = bpf_htonl(iph->daddr);
      struct session_id* session =
          bpf_map_lookup_elem(&m_session_mapping, ue_ip_out);

      // Check if the QoS enforcement is enabled:
      if (session) {
        u64 key = session->seid;
        if (bpf_map_lookup_elem(&m_qos_enabling, &key)) {
          u8 protocol = iph->protocol;

          packet_filter_out->src_ip   = bpf_htonl(iph->saddr);
          packet_filter_out->dst_ip   = *ue_ip_out;
          packet_filter_out->protocol = iph->protocol;

          switch (protocol) {
            case IPPROTO_UDP: {
              struct udphdr* udph = (struct udphdr*) (iph + 1);

              if ((void*) (udph + 1) > data_end) {
                bpf_debug("Error: Invalid UDP header");
                return NULL;
              }

              packet_filter_out->src_port = bpf_htons(udph->source);
              packet_filter_out->dst_port = bpf_htons(udph->dest);
              break;
            }
            case IPPROTO_TCP: {
              struct tcphdr* tcph = (struct tcphdr*) (iph + 1);

              if ((void*) (tcph + 1) > data_end) {
                bpf_debug("Error: Invalid TCP header");
                return NULL;
              }

              packet_filter_out->src_port = bpf_htons(tcph->source);
              packet_filter_out->dst_port = bpf_htons(tcph->dest);
              break;
            }
            case IPPROTO_ICMP: {
              packet_filter_out->src_port = 0;
              packet_filter_out->dst_port = 0;
              break;
            }
            default: {
              bpf_debug("Use best effort QoS flow (i.e. default qfi)");
              packet_filter_out->src_port = 0;
              packet_filter_out->dst_port = 0;
            }
          }
        }
      }
      return session;
    }
    case ETH_P_IPV6: {
      bpf_debug("Error: Unsupported IPv6 packet");
      return NULL;
    }
    case ETH_P_ARP: {
      bpf_debug("Info: This is an ARP packet");
      return NULL;
    }
    case ETH_P_8021Q: {
      bpf_debug("Info: This is a VLAN packet");
      return NULL;
    }
    case ETH_P_8021AD: {
      bpf_debug("This is a VLAN packet");
      return NULL;
    }

    default: {
      bpf_debug("Error: Unknown L3 packet");
      return NULL;
    }
  }
}

//--------------------------------------------------------------------------------------
static __always_inline pfcp_pdr_t_* pfcp_session_s_lookup_precedence_over_n6(
    u64 seid, u32 packet_ue_ip, u8* qfi_out,
    struct packet_filter* packet_filter) {
  pfcp_pdr_t_(*pdrs)[MAX_PDRS_PER_SESSION] =
      bpf_map_lookup_elem(&m_session_pdrs, &seid);

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
    u32 ipaddr                 = bpf_htonl(pdi.ue_ip_address.ipv4_address);

    if (ipaddr == packet_ue_ip) {
      u32 source_interface = pdi.source_interface.interface_value;
      bpf_debug(
          "N6 PDR Lookup: PDR_ID=%u, Precedence=%u, UE_IP=%pI4",
          pdr_high_prec->pdr_id.rule_id, pdr_high_prec->precedence.precedence,
          &ipaddr);

      switch (source_interface) {
        case INTERFACE_VALUE_ACCESS: {
          // bpf_debug(
          //     "Info: We should extract this case from the Map on
          //     downlink");
          break;
        }
        case INTERFACE_VALUE_CORE: {
          bpf_debug(
              "( packet_ue_ip,  pdi.ue_ip_address ) : ( %pI4, %pI4 )",
              &packet_ue_ip, &ipaddr);

          bpf_debug(
              "pdi.source_interface.interface_value: %d",
              pdi.source_interface.interface_value);
          *qfi_out = pdi.qfi.qfi;
          // Check if the QoS enforcement is enabled:
          u32* enabling_qos = bpf_map_lookup_elem(&m_qos_enabling, &seid);

          if (!enabling_qos) {
            bpf_debug(
                "Qos enforcement not enabled for Session %llu, returning PDR "
                "%u",
                seid, pdr_high_prec->pdr_id.rule_id);
            return pdr_high_prec;
          } else {
            struct session_qfi sdf_key = {0};
            sdf_key.seid               = seid;
            sdf_key.qfi                = *qfi_out;

            const struct sdf_filtr* sdf =
                bpf_map_lookup_elem(&m_sdf_filter, &sdf_key);
            if (!sdf) {
              bpf_debug(
                  "SDF Filter not found for QFI %u! Treating as "
                  "NON-GBR/default traffic",
                  *qfi_out);
              bpf_debug(
                  "Returning PDR %u (Precedence: %u) as default rule",
                  pdr_high_prec->pdr_id.rule_id,
                  pdr_high_prec->precedence.precedence);
              // TODO:
              // Treat default qos flow here !!!
              return pdr_high_prec;
            }
            bpf_debug(
                "SDF key ( seid, qfi ): ( %llu, %u )", sdf_key.seid,
                sdf_key.qfi);
            if (match_sdf_filter_ipv4(packet_filter, sdf)) {
              bpf_debug(
                  "SDF Match! Returning PDR %u (Precedence: %u)",
                  pdr_high_prec->pdr_id.rule_id,
                  pdr_high_prec->precedence.precedence);
              return pdr_high_prec;
            } else {
              bpf_debug(
                  "SDF filter did NOT match for PDR %u, continuing to next PDR",
                  pdr_high_prec->pdr_id.rule_id);
            }

            break;
          }
        }
        case INTERFACE_VALUE_SGI_LAN_N6_LAN: {
          // TODO: Perform actions here
          break;
        }
        case INTERFACE_VALUE_LI_FUNCTION: {
          // TODO: Perform actions here
          break;
        }

        default: {
          // TODO: Perform actions here
          break;
        }
      }
    }
  }
  return NULL;
}

//--------------------------------------------------------------------------------------

static __always_inline int entry_point_uplink__ip_pdu(struct xdp_md* ctx) {
  bpf_debug("================< XDP: Handle Uplink >================");
  /*
    |-----------------------------------------------------------------------|
    |----------------------------- N3 Entry Point --------------------------|
    |-----------------------------------------------------------------------|
    */
  void* data          = (void*) (long) ctx->data;
  void* data_end      = (void*) (long) ctx->data_end;
  struct ethhdr* ethh = data;

  if ((void*) (ethh + 1) > (void*) (long) ctx->data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return XDP_DROP;
  }

  /*
    |-----------------------------------------------------------------------|
    |-------------------------- PFCP Session Lookup ------------------------|
    |----------------- (Find PFCP session with matching PDRs) --------------|
    |-----------------------------------------------------------------------|
    */
  u32 ue_ip = 0;
  u8 qfi    = 0;

  struct session_id* session =
      pfcp_session_lookup_over_n3(data, data_end, ethh, &ue_ip, &qfi);

  if (!session) {
    bpf_debug(
        "PFCP Session Lookup (Find PFCP session with matching PDRs) failed");
    return XDP_PASS;
  }

  u64 seid    = session->seid;
  u32 teid_ul = bpf_htonl(session->teid_ul);
  u32 teid_dl = bpf_htonl(session->teid_dl);
  bpf_debug(
      "Session found ( seid, teid_ul, teid_dl ) : ( %llu, %u, %u )", seid,
      teid_ul, teid_dl);

  // Extract inner IP header for SDF filtering
  struct iphdr* outer_iph = (struct iphdr*) (ethh + 1);
  if ((void*) (outer_iph + 1) > data_end) {
    return XDP_PASS;
  }

  struct udphdr* udph = (struct udphdr*) (outer_iph + 1);
  if ((void*) (udph + 1) > data_end) {
    return XDP_PASS;
  }

  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    return XDP_PASS;
  }

  struct gtpu_extn_pdu_session_container* ext_gtpuh =
      (struct gtpu_extn_pdu_session_container*) (gtpuh + 1);
  if ((void*) (ext_gtpuh + 1) > data_end) {
    return XDP_PASS;
  }

  struct iphdr* inner_iph = (struct iphdr*) (ext_gtpuh + 1);
  if ((void*) (inner_iph + 1) > data_end) {
    return XDP_PASS;
  }

  // Get L4 header (TCP/UDP)
  void* l4_hdr = (void*) (inner_iph + 1);
  if ((void*) l4_hdr + sizeof(struct udphdr) > data_end) {
    return XDP_PASS;
  }

  /*
    |-----------------------------------------------------------------------|
    |------------------------ PFCP Session's Lookup ------------------------|
    |--- (Find matching PDR of the PFCP session with highest precedence) ---|
    |-----------------------------------------------------------------------|
    */
  pfcp_pdr_t_* pdr_high_precedence = pfcp_session_s_lookup_precedence_over_n3(
      seid, teid_ul, ue_ip, qfi, inner_iph, l4_hdr, data_end);

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

  u32 ret = apply_rules_matching_pdr_over_n3(ctx, ethh, key_rules_matching_pdr);
  switch (ret) {
    case REDIRECT: {
      return bpf_redirect_map(&m_redirect_interfaces, UPLINK, 0);
      bpf_debug("Redirect: failed to redirect traffic to N6");
      break;
    }
    case DROP: {
      bpf_debug("DROP: Packet should be dropped");
      return XDP_DROP;
    }
    case FAILURE: {
      bpf_debug("failed to apply matching rules for PDR");
    }
    default: {
      bpf_debug("PASS: something went wrong! pass packet to kernel");
      return XDP_PASS;
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
SEC("xdp")
int xdp_handle_uplink(struct xdp_md* ctx) {
  bpf_debug("================< PFCP PDR UL Sesction >================");
  struct ethhdr* ethh = (void*) (long) ctx->data;
  int action          = XDP_PASS;

  action = entry_point_uplink__ip_pdu(ctx);

  // When entry_point_uplink__ip_pdu returns XDP_PASS, this could be an ETH PDU
  // PACKET (for DL and DL)
  if (action != XDP_PASS) {
    return action;
  }

  action = entry_point_uplink__eth_pdu(ctx);

  return action;
}

/*---------------------------------------------------------------------------------------------------------------*/
SEC("xdp")
int xdp_handle_shaping(struct xdp_md* ctx) {
  bpf_debug("================< XDP: Handle Shaping >================");
  /*
   |-----------------------------------------------------------------------|
   |----------------------------- N6 Entry Point --------------------------|
   |-----------------------------------------------------------------------|
   */

  // struct packet_filter* packet_filter = {0};
  // struct packet_filter* key;
  struct session_qfi* qos_metadata = {0};

  if (bpf_xdp_adjust_meta(ctx, -(int) sizeof(struct session_qfi))) {
    bpf_debug("Error: Unable to reserve metadata space");
    return XDP_DROP;
  }

  void* data          = (void*) (long) ctx->data;
  void* data_end      = (void*) (long) ctx->data_end;
  struct ethhdr* ethh = data;

  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return XDP_DROP;
  }

  /*
    |-----------------------------------------------------------------------|
    |-------------------------- PFCP Session Lookup ------------------------|
    |----------------- (Find PFCP session with matching PDRs) --------------|
    |-----------------------------------------------------------------------|
    */
  u32 ue_ip                          = 0;
  struct packet_filter packet_filter = {0};

  struct session_id* session =
      pfcp_session_lookup_over_n6(data, data_end, ethh, &ue_ip, &packet_filter);

  if (!session) {
    bpf_debug(
        "PFCP Session Lookup (Find PFCP session with matching PDRs) failed");
    return XDP_PASS;
  }

  u64 seid    = session->seid;
  u32 teid_ul = bpf_htonl(session->teid_ul);
  u32 teid_dl = bpf_htonl(session->teid_dl);
  bpf_debug(
      "Session found ( seid, teid_ul, teid_dl ) : ( %llu, %u, %u )", seid,
      teid_ul, teid_dl);

  /*
   |-----------------------------------------------------------------------|
   |------------------------ PFCP Session's Lookup ------------------------|
   |--- (Find matching PDR of the PFCP session with highest precedence) ---|
   |-----------------------------------------------------------------------|
   */
  u8 qfi                           = 0;
  pfcp_pdr_t_* pdr_high_precedence = pfcp_session_s_lookup_precedence_over_n6(
      seid, ue_ip, &qfi, &packet_filter);

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
  qos_metadata = (struct session_qfi*) (long) ctx->data_meta;
  if ((void*) (qos_metadata + 1) > data) {
    bpf_debug("Error: Invalid Metadata");
    return XDP_DROP;
  }

  qos_metadata->seid = seid;
  qos_metadata->qfi  = qfi;

  struct pdrs_per_session key_rules_matching_pdr = {0};
  key_rules_matching_pdr.pdr_id                  = pdr_id;
  key_rules_matching_pdr.seid                    = seid;

  u32 ret =
      apply_rules_matching_pdr_over_n6(ctx, ethh, key_rules_matching_pdr, qfi);

  switch (ret) {
    case PASS: {
      bpf_debug("PASS: Pass the packet to TC layer");
      return XDP_PASS;
    }
    case REDIRECT: {
      return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
      bpf_debug("Redirect: failed to redirect traffic to N3");
      return XDP_DROP;
    }
    case DROP: {
      bpf_debug("DROP: Packet should be dropped");
      return XDP_DROP;
    }
    default: {
      bpf_debug("PASS: something went wrong! pass packet to kernel");
      return XDP_PASS;
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline int entry_point_downlink__ip_pdu(struct xdp_md* ctx) {
  bpf_debug("================< XDP: Handle Downlink >================");
  /*
   |-----------------------------------------------------------------------|
   |----------------------------- N6 Entry Point --------------------------|
   |-----------------------------------------------------------------------|
   */
  void* data          = (void*) (long) ctx->data;
  void* data_end      = (void*) (long) ctx->data_end;
  struct ethhdr* ethh = data;

  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return XDP_DROP;
  }

  /*
    |-----------------------------------------------------------------------|
    |-------------------------- PFCP Session Lookup ------------------------|
    |----------------- (Find PFCP session with matching PDRs) --------------|
    |-----------------------------------------------------------------------|
    */
  u32 ue_ip                          = 0;
  struct packet_filter packet_filter = {0};
  struct session_id* session =
      pfcp_session_lookup_over_n6(data, data_end, ethh, &ue_ip, &packet_filter);

  if (!session) {
    bpf_debug(
        "PFCP Session Lookup (Find PFCP session with matching PDRs) failed");
    return XDP_PASS;
  }

  u64 seid    = session->seid;
  u32 teid_ul = bpf_htonl(session->teid_ul);
  u32 teid_dl = bpf_htonl(session->teid_dl);
  bpf_debug(
      "Session found ( seid, teid_ul, teid_dl ) : ( %llu, %u, %u )", seid,
      teid_ul, teid_dl);

  /*
     |-----------------------------------------------------------------------|
     |------------------------ PFCP Session's Lookup ------------------------|
     |--- (Find matching PDR of the PFCP session with highest precedence) ---|
     |-----------------------------------------------------------------------|
     */
  u8 qfi                           = 0;
  pfcp_pdr_t_* pdr_high_precedence = pfcp_session_s_lookup_precedence_over_n6(
      seid, ue_ip, &qfi, &packet_filter);

  if (!pdr_high_precedence) {
    bpf_debug(
        "PFCP Session's Lookup (Find matching PDR of the PFCP session with "
        "highest precedence) failed");
    return XDP_PASS;
  }

  u32 pdr_id = pdr_high_precedence->pdr_id.rule_id;
  bpf_debug("Highest precedence PDR found %d", pdr_id);

  /*
    |-----------------------------------------------------------------------|
    |--------------------- Apply Rules in Matching PDR ---------------------|
    |----------------------------- (FARs, QERs) ----------------------------|
    |-----------------------------------------------------------------------|
    */
  struct pdrs_per_session key_rules_matching_pdr = {0};
  key_rules_matching_pdr.pdr_id                  = pdr_id;
  key_rules_matching_pdr.seid                    = seid;

  u32 ret =
      apply_rules_matching_pdr_over_n6(ctx, ethh, key_rules_matching_pdr, qfi);

  switch (ret) {
    case REDIRECT: {
      return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
      bpf_debug("Redirect: failed to redirect traffic to N6");
      break;
    }
    case DROP: {
      bpf_debug("DROP: Packet should be droped");
      return XDP_DROP;
    }
    default: {
      bpf_debug("PASS: something went wrong! pass packet to kernel");
      return XDP_PASS;
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
SEC("xdp")
int xdp_handle_downlink(struct xdp_md* ctx) {
  bpf_debug("================< PFCP PDR DL Sesction >================");
  struct ethhdr* ethh = (void*) (long) ctx->data;
  void* data_end      = (void*) (long) ctx->data_end;
  int action          = XDP_PASS;

  action = entry_point_downlink__ip_pdu(ctx);

  // When eth_handle returns XDP_PASS, this could be an ETH PDU PACKET (for DL
  // and DL)
  if (action != XDP_PASS) {
    return action;
  }

  action = entry_point_downlink__eth_pdu(ctx);

  return action;
}

char _license[] SEC("license") = "GPL";
