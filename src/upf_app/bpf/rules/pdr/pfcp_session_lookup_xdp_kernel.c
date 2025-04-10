#define KBUILD_MODNAME pfcp_session_lookup_xdp_kernel

#include <types.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <endian.h>
#include <lib/crc16.h>
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
#include <next_prog_rule_key.h>

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

#define MAX_PDRS_PER_SESSION 32

/*---------------------------------------------------------------------------------------------------------------*/
static __always_inline bool update_dst_mac_address(
    u32 ip, struct ethhdr* p_eth) {
  struct s_arp_mapping* map_entry = {0};
  // memset(&map_entry, 0, sizeof(struct s_arp_mapping));

  map_entry = bpf_map_lookup_elem(&m_arp_table, &ip);

  if (map_entry) {
    memcpy(p_eth->h_dest, map_entry->mac_address, sizeof(p_eth->h_dest));
    return true;
  }

  return false;
}

static __always_inline u32 match_sdf_filter_ipv4(
    const struct packet_filter* filter, const struct sdf_filtr* sdf) {
  u8 packet_protocol  = filter->protocol;
  u16 packet_src_port = filter->src_port;
  u16 packet_dst_port = filter->dst_port;
  u32 packet_src_ip   = bpf_htonl(filter->src_ip);
  u32 packet_dst_ip   = bpf_htonl(filter->dst_ip);

  u32 sdf_src_ip   = bpf_htonl(sdf->src_addr.ip);
  u32 sdf_dst_ip   = bpf_htonl(sdf->dst_addr.ip);
  u32 sdf_src_mask = bpf_htonl(sdf->src_addr.mask);
  u32 sdf_dst_mask = bpf_htonl(sdf->dst_addr.mask);

  bpf_debug("SDF: filter protocol: %u", sdf->protocol);
  bpf_debug(
      "SDF: filter source ip: %pI4, destination ip: %pI4", &sdf_src_ip,
      &sdf_dst_ip);
  bpf_debug(
      "SDF: filter source ip mask: %pI4, destination ip mask: %pI4",
      &sdf_src_mask, &sdf_dst_mask);
  bpf_debug(
      "SDF: filter source port lower bound: %u, source port upper bound: %u",
      sdf->src_port.lower_bound, sdf->src_port.upper_bound);
  bpf_debug(
      "SDF: filter destination port lower bound: %u, destination port upper "
      "bound: %u",
      sdf->dst_port.lower_bound, sdf->dst_port.upper_bound);

  bpf_debug("SDF: packet protocol: %u", packet_protocol);
  bpf_debug(
      "SDF: packet source ip: %pI4, destination ip: %pI4", &packet_src_ip,
      &packet_dst_ip);
  bpf_debug(
      "SDF: packet source port: %u, destination port: %u", packet_src_port,
      packet_dst_port);

  // TODO: Start with the hit and not miss
  /*
   * TODO:
   * 1. Start with the hit and not miss
   * 2. Check if an enum is really needed to redifine protocol:
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
  if ((sdf->protocol == 1 || sdf->protocol == packet_protocol) &&
      ((packet_src_ip & sdf_src_mask) == sdf_src_ip) &&
      ((packet_dst_ip & sdf_dst_mask) == sdf_dst_ip) &&
      (packet_src_port >= sdf->src_port.lower_bound &&
       packet_src_port <= sdf->src_port.upper_bound) &&
      (packet_dst_port >= sdf->dst_port.lower_bound &&
       packet_dst_port <= sdf->dst_port.upper_bound)) {
    return 1;
  }

  bpf_debug("Packet Metadata and SDF are matching");
  return 0;
}

/*---------------------------------------------------------------------------------------------------------------*/

static __always_inline u32
create_outer_header_gtpu_ipv4(struct xdp_md* ctx, pfcp_far_t_* p_far) {
  // Adjust space to the left.
  if (bpf_xdp_adjust_head(ctx, (int32_t) -GTP_ENCAPSULATED_SIZE)) {
    return XDP_DROP;
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
      return XDP_DROP;
    }

    upf_n3_ip = map_element->ipv4_address;
    cached_n3 = true;
  }

  struct s_arp_mapping* map_entry = {0};
  map_entry = bpf_map_lookup_elem(&m_arp_table, &upf_n3_ip);

  if (!map_entry) {
    bpf_debug("N3's Next Hop MAC address not found! Drop the packet");
    return XDP_DROP;
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
    bpf_debug("Invalid pointer");
    return XDP_DROP;
  }

  struct ethhdr* ethh_orig = data + GTP_ENCAPSULATED_SIZE;

  if ((void*) (ethh_orig + 1) > data_end) {
    bpf_debug("Invalid Pointer");
    return XDP_DROP;
  }
  __builtin_memcpy(ethh, ethh_orig, sizeof(*ethh));

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add IP header -----------------------|
  |----------------------------------------------------------------|
  */
  struct iphdr* iph = (void*) (ethh + 1);
  if ((void*) (iph + 1) > data_end) {
    return XDP_DROP;
  }

  struct iphdr* p_inner_ip = (void*) iph + GTP_ENCAPSULATED_SIZE;
  if ((void*) (p_inner_ip + 1) > data_end) {
    return XDP_DROP;
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

  bpf_debug("IP SRC: %pI4, IP DST: %pI4", iph->saddr, iph->daddr);

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
    return XDP_DROP;
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
    return XDP_DROP;
  }

  p_gtpu_ext_h->message_length = GTP_EXT_MSG_LEN;
  p_gtpu_ext_h->pdu_type       = GTP_EXT_PDU_TYPE;
  // p_gtpu_ext_h->qfi            = GTP_EXT_QFI;
  p_gtpu_ext_h->qfi           = GTP_DEFAULT_QFI;
  p_gtpu_ext_h->next_ext_type = GTP_EXT_NEXT_EXT_TYPE;

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
        bpf_debug("Error: Invalid IPv4 Packet");
        return NULL;
      }

      struct udphdr* udph = (struct udphdr*) (iph + 1);
      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Error: Invalid UDP packet");
        return NULL;
      }

      if (bpf_htons(udph->dest) != GTP_UDP_PORT) {
        bpf_debug("Error: Invalid GTP Port");
        return NULL;
      }

      bpf_debug("Identified GTP Traffic");

      struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);
      if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
        bpf_debug("Error: Invalid GTP-U packet");
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
        bpf_debug("Error: Invalid GTPU Extension packet");
        return NULL;
      }

      struct iphdr* iph_inner = (struct iphdr*) (ext_gtpuh + 1);
      if ((void*) (iph_inner + 1) > data_end) {
        bpf_debug("Error: Invalid Inner IP packet");
        return NULL;
      }

      *ue_ip_out = bpf_htonl(iph_inner->saddr);
      *qfi_out   = ext_gtpuh->qfi;
      return bpf_map_lookup_elem(&m_session_mapping, ue_ip_out);
    }
    case ETH_P_IPV6: {
      bpf_debug("Error: Unsupported IPv6 Packet");
      return NULL;
    }
    case ETH_P_ARP: {
      bpf_debug("Info: This is an ARP Packet");
      return NULL;
    }
    case ETH_P_8021Q: {
      bpf_debug("Info: This is a VLAN Packet");
      return NULL;
    }
    case ETH_P_8021AD: {
      bpf_debug("This is a VLAN Packet");
      return NULL;
    }

    default: {
      bpf_debug("Error: Unknown L3 Packet");
      return NULL;
    }
  }
}

//--------------------------------------------------------------------------------------

static __always_inline pfcp_pdr_t_* pfcp_session_s_lookup_precedence_over_n3(
    u64 seid, u32 packet_teid, u32 packet_ue_ip, u8 packet_qfi) {
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

    if ((ipaddr == packet_ue_ip) &&
        (bpf_htonl(pdi.source_interface.interface_value) ==
         INTERFACE_VALUE_ACCESS)) {
      // After uplink/downlink separation, we can remove the source_interface
      // check

      bpf_debug(
          "( packet_ue_ip,  pdi.ue_ip_address ) : ( %pI4, %pI4 )",
          &packet_ue_ip, &ipaddr);
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

//--------------------------------------------------------------------------------------
static __always_inline u32 apply_rules_matching_pdr_over_n3(
    struct xdp_md* ctx, struct ethhdr* ethh,
    struct pdrs_per_session key_rules_matching_pdr) {
  void* data                    = (void*) (long) ctx->data;
  void* data_end                = (void*) (long) ctx->data_end;
  struct rules_match_pdr* rules = {0};
  u64 seid                      = key_rules_matching_pdr.seid;

  rules = bpf_map_lookup_elem(&m_rules_match_pdr, &key_rules_matching_pdr);

  if (!rules) {
    bpf_debug("No rule was found for the PDR");
    return XDP_PASS;
  }
  pfcp_far_t_* far = &rules->far;

  if (far) {
    bpf_debug("FAR ID = %d", far->far_id.far_id);

    if (!far->apply_action.forw) {
      bpf_debug("Forward Action Is NOT set");
      return XDP_PASS;
    }

    bpf_debug("GTP Header Removal in Progress");

    struct ethhdr* new_ethh = data + GTP_ENCAPSULATED_SIZE;
    if ((void*) new_ethh + sizeof(*new_ethh) > data_end) {
      bpf_debug("Error: Invalid encapsulated Ethernet packet");
      return XDP_DROP;
    }
    __builtin_memcpy(new_ethh, ethh, sizeof(*ethh));

    e_reference_point n6_key = N6_INTERFACE;

    // if (!cached_n6) {
    struct s_interface* map_element =
        bpf_map_lookup_elem(&m_upf_interfaces, &n6_key);

    if (!map_element) {
      bpf_debug("N6 interface is missing in UPF map, Drop the packet");
      return XDP_DROP;
    }

    upf_n6_ip = map_element->ipv4_address;

    struct s_arp_mapping* map_entry = {0};
    map_entry = bpf_map_lookup_elem(&m_arp_table, &upf_n6_ip);

    if (!map_entry) {
      bpf_debug("N6's Next Hop MAC address not found! Drop the packet");
      return XDP_DROP;
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
      return XDP_DROP;
    }

    bpf_debug("Redirecting Packet to DN");

    return bpf_redirect_map(&m_redirect_interfaces, UPLINK, 0);

    bpf_debug("OUTER_HEADER_CREATION_UDP_IPV4 REDIRECT FAILED");
  }

  bpf_debug("Forwarding Action (FAR) not found for session %llu", seid);
  return XDP_DROP;
}

//--------------------------------------------------------------------------------------
static __always_inline u32 apply_rules_matching_pdr_over_n6(
    struct xdp_md* ctx, struct ethhdr* ethh,
    struct pdrs_per_session key_rules_matching_pdr) {
  // void* data                    = (void*) (long) ctx->data;
  // void* data_end                = (void*) (long) ctx->data_end;
  struct rules_match_pdr* rules = {0};
  u64 seid                      = key_rules_matching_pdr.seid;

  rules = bpf_map_lookup_elem(&m_rules_match_pdr, &key_rules_matching_pdr);

  if (!rules) {
    bpf_debug("No rule was found for the PDR");
    return XDP_PASS;
  }

  pfcp_far_t_* far = &rules->far;
  if (far) {
    bpf_debug("FAR ID = %d", far->far_id.far_id);
    create_outer_header_gtpu_ipv4(ctx, far);

    u32* qos_enabling = bpf_map_lookup_elem(&m_qos_enabling, &seid);
    if (!qos_enabling) {
      bpf_debug("QoS Enforcement is Disabled for PDU session %llu", seid);
      return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
    } else {
      pfcp_qer_t_* qer = &rules->qer;
      if (qer->gate_status.dl_gate == 1) {
        return XDP_PASS;
      } else {
        bpf_debug("Gate is close for Session %llu. Drop all traffic", seid);
        return XDP_DROP;
      }
    }
  }

  bpf_debug("Forwarding Action (FAR) not found for session %llu", seid);

  return XDP_PASS;
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
        bpf_debug("Error: Invalid IPv4 Packet");
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

              packet_filter_out->src_port = udph->source;
              packet_filter_out->dst_port = udph->dest;
              break;
            }
            case IPPROTO_TCP: {
              struct tcphdr* tcph = (struct tcphdr*) (iph + 1);

              if ((void*) (tcph + 1) > data_end) {
                bpf_debug("Error: Invalid TCP header");
                return NULL;
              }

              packet_filter_out->src_port = tcph->source;
              packet_filter_out->dst_port = tcph->dest;
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
      bpf_debug("Error: Unsupported IPv6 Packet");
      return NULL;
    }
    case ETH_P_ARP: {
      bpf_debug("Info: This is an ARP Packet");
      return NULL;
    }
    case ETH_P_8021Q: {
      bpf_debug("Info: This is a VLAN Packet");
      return NULL;
    }
    case ETH_P_8021AD: {
      bpf_debug("This is a VLAN Packet");
      return NULL;
    }

    default: {
      bpf_debug("Error: Unknown L3 Packet");
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

    if (bpf_htonl(pdi.ue_ip_address.ipv4_address) == packet_ue_ip) {
      u32 source_interface = pdi.source_interface.interface_value;
      switch (source_interface) {
        case INTERFACE_VALUE_ACCESS: {
          // bpf_debug(
          //     "Info: We should extract this case from the Map on downlink");
          break;
        }
        case INTERFACE_VALUE_CORE: {
          bpf_debug(
              "( packet_ue_ip,  pdi.ue_ip_address ) : ( %pI4, %pI4 )",
              &packet_ue_ip, &ipaddr);

          bpf_debug(
              "pdi.source_interface.interface_value: %d",
              pdi.source_interface.interface_value);
          // Check if the QoS enforcement is enabled:
          u32* enabling_qos = bpf_map_lookup_elem(&m_qos_enabling, &seid);
          if (!enabling_qos) {
            bpf_debug("Qos enforcement not ebabled for Session %llu", seid);
          } else {
            *qfi_out                   = pdi.qfi.qfi;
            struct session_qfi sdf_key = {0};
            sdf_key.seid               = seid;
            sdf_key.qfi                = *qfi_out;

            const struct sdf_filtr* sdf =
                bpf_map_lookup_elem(&m_sdf_filter, &sdf_key);
            if (!sdf) {
              bpf_debug("SDF Filter not found! This is a NON-GBR Traffic");
              // TODO:
              // Treat default qos flow here !!!
              break;
            }
            bpf_debug(
                "SDF key ( seid, qfi ): ( %llu, %u )", sdf_key.seid,
                sdf_key.qfi);
            if (match_sdf_filter_ipv4(packet_filter, sdf)) {
              bpf_debug("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
              return pdr_high_prec;
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

SEC("xdp")
int xdp_handle_uplink(struct xdp_md* ctx) {
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

  /*
    |-----------------------------------------------------------------------|
    |------------------------ PFCP Session's Lookup ------------------------|
    |--- (Find matching PDR of the PFCP session with highest precedence) ---|
    |-----------------------------------------------------------------------|
    */
  pfcp_pdr_t_* pdr_high_precedence =
      pfcp_session_s_lookup_precedence_over_n3(seid, teid_ul, ue_ip, qfi);

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
    |--------------------- Apply RUles in Matching PDR ---------------------|
    |----------------------------- (FARs, QERs) ----------------------------|
    |-----------------------------------------------------------------------|
    */
  struct pdrs_per_session key_rules_matching_pdr = {0};
  key_rules_matching_pdr.pdr_id                  = pdr_id;
  key_rules_matching_pdr.seid                    = seid;

  apply_rules_matching_pdr_over_n3(ctx, ethh, key_rules_matching_pdr);
}

/*---------------------------------------------------------------------------------------------------------------*/

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
    |--------------------- Apply RUles in Matching PDR ---------------------|
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

  apply_rules_matching_pdr_over_n6(ctx, ethh, key_rules_matching_pdr);
}

/*---------------------------------------------------------------------------------------------------------------*/
SEC("xdp")
int xdp_handle_downlink(struct xdp_md* ctx) {
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
    bpf_debug("Session lookup failed");
    return XDP_PASS;
  }

  u64 seid    = session->seid;
  u32 teid_ul = session->teid_ul;
  bpf_debug("Session found, SEID = %llu", seid);
  bpf_debug("TEID_UL = %x", teid_ul);
  bpf_debug("TEID_DL = %x", session->teid_dl);
  bpf_debug("UE = %pI4", ue_ip);

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
    bpf_debug("Session lookup failed");
    return XDP_PASS;
  }

  u32 pdr_id = pdr_high_precedence->pdr_id.rule_id;
  bpf_debug("Highest precedence PDR found %d", pdr_id);

  /*
    |-----------------------------------------------------------------------|
    |--------------------- Apply RUles in Matching PDR ---------------------|
    |----------------------------- (FARs, QERs) ----------------------------|
    |-----------------------------------------------------------------------|
    */
  struct pdrs_per_session key_rules_matching_pdr = {0};
  key_rules_matching_pdr.pdr_id                  = pdr_id;
  key_rules_matching_pdr.seid                    = seid;
  apply_rules_matching_pdr_over_n6(ctx, ethh, key_rules_matching_pdr);
}

char _license[] SEC("license") = "GPL";
