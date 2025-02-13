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

#include <pfcp_session_lookup_maps.h>
#include <far_maps.h>
#include <interfaces.h>

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
static u8 next_hop_n6_mac_address[6] = {0};

static bool cached_n3 = false;
static bool cached_n6 = false;

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

/*---------------------------------------------------------------------------------------------------------------*/

static __always_inline u32
create_outer_header_gtpu_ipv4(struct xdp_md* ctx, pfcp_far_t_* p_far) {
  // bpf_debug("Create Outer Header GTPU_IPv4");
  // bpf_debug("Original Packet: Data/UDP/IP/ETH");

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

  bpf_debug("IP SRC: 0x%x, IP DST: 0x%x", iph->saddr, iph->daddr);

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

SEC("xdp")
int xdp_handle_uplink(struct xdp_md* ctx) {
  bpf_debug("================< XDP: Handle Uplink >================");

  void* data          = (void*) (long) ctx->data;
  void* data_end      = (void*) (long) ctx->data_end;
  struct ethhdr* ethh = (void*) (long) ctx->data;

  if ((void*) (ethh + 1) > (void*) (long) ctx->data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return XDP_DROP;
  }

  u16 eth_type = bpf_htons(ethh->h_proto);
  bpf_debug("Debug: eth_type:0x%x", eth_type);

  switch (eth_type) {
    case ETH_P_IP: {
      struct iphdr* iph = (struct iphdr*) ((void*) ethh + sizeof(*ethh));

      if ((void*) (iph + 1) > data_end) {
        bpf_debug("Error: Invalid IPv4 Packet");
        return XDP_DROP;
      }

      struct udphdr* udph = (struct udphdr*) (iph + 1);

      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Error: Invalid UDP packet");
        return XDP_DROP;
      }

      if (bpf_htons(udph->dest) == GTP_UDP_PORT) {
        bpf_debug("Identified GTP Traffic");

        struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);

        if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
          bpf_debug("Error: Invalid GTP-U packet");
          return XDP_DROP;
        }

        if (gtpuh->message_type != GTPU_G_PDU) {
          bpf_debug(
              "Message type 0x%x is not GTPU GPDU(0x%x)\n", gtpuh->message_type,
              GTPU_G_PDU);
          return XDP_PASS;
        }

        struct ethhdr* ethh_new = data + GTP_ENCAPSULATED_SIZE;

        if ((void*) ethh_new + sizeof(*ethh_new) > data_end) {
          bpf_debug("Error: Invalid encapsulated Ethernet packet");
          return XDP_DROP;
        }

        struct iphdr* iph_inner = (void*) (ethh_new + 1);

        if ((void*) iph_inner + sizeof(*iph_inner) > data_end) {
          bpf_debug("Error: Invalid Inner IP packet");
          return XDP_DROP;
        }

        u32 src_ip_in = bpf_htonl(iph_inner->saddr);

        struct next_rule_prog_index_key map_key = {0};
        map_key.teid                            = gtpuh->teid;
        map_key.source_value                    = INTERFACE_VALUE_ACCESS;
        map_key.ipv4_address                    = src_ip_in;

        pfcp_far_t_* p_far =
            bpf_map_lookup_elem(&m_next_rule_prog_index, &map_key);

        if (p_far) {
          bpf_debug("FAR ID = %d", p_far->far_id.far_id);
          // u8 dest_interface =
          // p_far->forwarding_parameters.destination_interface.interface_value;

          if (!p_far->apply_action.forw) {
            bpf_debug("Forward Action Is NOT set");
            return XDP_PASS;
          }

          bpf_debug("GTP Header Removal in Progress");

          __builtin_memcpy(ethh_new, ethh, sizeof(*ethh));

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

          //   memcpy(
          //       next_hop_n6_mac_address, map_entry->mac_address,
          //       sizeof(next_hop_n6_mac_address));

          //   cached_n6 = true;
          // }

          // memcpy(
          //     ethh_new->h_dest, next_hop_n6_mac_address,
          //     sizeof(ethh_new->h_dest));

          memcpy(
              ethh_new->h_dest, map_entry->mac_address,
              sizeof(ethh_new->h_dest));

          bpf_debug(
              "Destination MAC  %x:%x:%x:", ethh_new->h_dest[0],
              ethh_new->h_dest[1], ethh_new->h_dest[2]);
          bpf_debug(
              " %x:%x:%x", ethh_new->h_dest[3], ethh_new->h_dest[4],
              ethh_new->h_dest[5]);

          // Adjust head to the right.
          if (bpf_xdp_adjust_head(ctx, GTP_ENCAPSULATED_SIZE)) {
            bpf_debug("Error: Adjusting packet head failed");
            return XDP_DROP;
          }

          bpf_debug("Redirecting Packet to DN");

          return bpf_redirect_map(&m_redirect_interfaces, UPLINK, 0);

          bpf_debug("OUTER_HEADER_CREATION_UDP_IPV4 REDIRECT FAILED");
        }

        return XDP_PASS;
      }
    }
    default: {
      bpf_debug("Unsupported protocol: 0x%x", eth_type);
      return XDP_PASS;
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
SEC("xdp")
int xdp_handle_downlink(struct xdp_md* ctx) {
  bpf_debug("================< XDP: Handle Downlink >================");

  void* data_end      = (void*) (long) ctx->data_end;
  struct ethhdr* ethh = (void*) (long) ctx->data;

  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return XDP_DROP;
  }

  // struct iphdr* iph = (struct iphdr*) ((void*) ethh + sizeof(*ethh));
  struct iphdr* iph = (void*) (ethh + 1);

  if ((void*) (iph + 1) > data_end) {
    bpf_debug("Error: Invalid IPv4 Packet");
    return XDP_DROP;
  }

  bpf_debug("Ip_dest: 0x%x", iph->daddr);
  u32 ip_dest = bpf_htonl(iph->daddr);
  struct session_id* session =
      bpf_map_lookup_elem(&m_session_mapping, &ip_dest);

  if (session) {
    u32 teid_dl = session->teid_dl;
    bpf_debug("TEID for downlink: 0x%x, UE IP: 0x%x", teid_dl, ip_dest);

    struct next_rule_prog_index_key map_key = {0};
    map_key.teid                            = teid_dl;
    map_key.source_value                    = INTERFACE_VALUE_CORE;
    map_key.ipv4_address                    = ip_dest;

    pfcp_far_t_* p_far = bpf_map_lookup_elem(&m_next_rule_prog_index, &map_key);

    if (p_far) {
      bpf_debug("FAR ID = %d", p_far->far_id.far_id);
      create_outer_header_gtpu_ipv4(ctx, p_far);

      return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
    }
  }

  bpf_debug("Session not found for Downlink");

  return XDP_PASS;
}

/*---------------------------------------------------------------------------------------------------------------*/
SEC("xdp")
int xdp_handle_shaping(struct xdp_md* ctx) {
  bpf_debug("================< XDP: Handle Shaping >================");

  void* data_end      = (void*) (long) ctx->data_end;
  struct ethhdr* ethh = (void*) (long) ctx->data;

  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return XDP_DROP;
  }
   
  /************************************************* */
  u16 eth_type = htons(ethh->h_proto);
  bpf_debug("eth_type: 0x%x", eth_type);

  switch (eth_type) {
    case ETH_P_IP: {
      bpf_debug("This is an IPv4 Packet");
      break;
    }
    case ETH_P_IPV6: {
      // TODO: Check if traitment is needed here
      bpf_debug("This is an IPv6 Packet");
      return XDP_DROP;
    }
    case ETH_P_8021Q: {
      // TODO: Check if traitment is needed here
      bpf_debug("This is a VLAN Packet");
      return XDP_DROP;
    }
    case ETH_P_8021AD: {
      // TODO: Check if traitment is needed here
      bpf_debug("This is a VLAN Packet");
      return XDP_DROP;
    }
    case ETH_P_ARP: {
      // TODO: Check if traitment is needed here
      bpf_debug("This is an ARP Packet");
      return XDP_PASS;
    }
    default: {
      // TODO: Check if traitment is needed here
      bpf_debug("Packet Type not Known");
      return XDP_DROP;
    }
  } 
  /************************************************* */
  // struct iphdr* iph = (struct iphdr*) ((void*) ethh + sizeof(*ethh));
  struct iphdr* iph = (void*) (ethh + 1);

  if ((void*) (iph + 1) > data_end) {
    bpf_debug("Error: Invalid IPv4 Packet");
    return XDP_DROP;
  }

  bpf_debug("000000 Shaping IP DST: 0x%x", iph->daddr);
  u32 ip_dest = bpf_htonl(iph->daddr);
  bpf_debug("11111 Shaping IP DST: %pI4", &ip_dest);

  struct session_id* session =
      bpf_map_lookup_elem(&m_session_mapping, &ip_dest);

  if (session) {
    u32 teid_dl = session->teid_dl;
    bpf_debug(
        "TEID downlink: 0x%x was found for UE IP: 0x%x", teid_dl, ip_dest);
    struct next_rule_prog_index_key map_key = {0};
    map_key.teid                            = teid_dl;
    map_key.source_value                    = INTERFACE_VALUE_CORE;
    map_key.ipv4_address                    = ip_dest;

    pfcp_far_t_* p_far = bpf_map_lookup_elem(&m_next_rule_prog_index, &map_key);

    if (p_far) {
      bpf_debug("FAR ID = %d", p_far->far_id.far_id);
      create_outer_header_gtpu_ipv4(ctx, p_far);
      bpf_debug("The packet is passed to tc layer");
      return XDP_PASS;
    }
  }

  bpf_debug("BPF tail call was not executed!");

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

/*---------------------------------------------------------------------------------------------------------------*/