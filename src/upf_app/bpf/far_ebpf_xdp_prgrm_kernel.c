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
#include <linux/tcp.h>
#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_pdr.h>
#include <protocols/gtpu.h>
#include <protocols/ip.h>
#include <protocols/tcp.h>
#include <utils/csum.h>
#include <utils/logger.h>
#include <utils/utils.h>
#include <far_maps.h>
#include <interfaces.h>
#include <pfcp_session_lookup_maps.h>
#include <string.h>  //Needed for memcpy
#include "bpf_endian.h"

/*****************************************************************************************************************/
// TODO: Put dummy in test folder.
/**
 * WARNING: Redirect require an XDP bpf_prog loaded on the TX device.
 */
// SEC("xdp_redirect_dummy")
// int xdp_redirect_gtpu(struct xdp_md* p_ctx) {
//   // PASS.
//   bpf_debug("Redirecting packets");
//   return XDP_PASS;
// }

/*****************************************************************************************************************/
/**
 * @brief Update MAC address
 *
 * @param p_ip The IP header which has the destination IP address.
 * @param [out] p_eth  The eth header with the new mac address.
 * @return 0 (Success), 1 (Fail).
 */

// static u32 update_dst_mac_address(struct iphdr* p_ip, struct ethhdr* p_eth) {
//   void* p_mac_address;

//   p_mac_address = bpf_map_lookup_elem(&m_arp_table, &p_ip->daddr);

//   if (!p_mac_address) {
//     bpf_debug("MAC Address NOT Found for IP addr: 0x%x", p_ip->daddr);
//     return 1;
//   }

//   memcpy(p_eth->h_dest, p_mac_address, sizeof(p_eth->h_dest));

//   return 0;
// }

// static u32 update_dst_mac_address(u32 ip, struct ethhdr* p_eth) {
//   struct s_arp_mapping* map_table;
//   memset(&map_table, 0, sizeof(struct s_arp_mapping));

//   map_table = bpf_map_lookup_elem(&m_arp_table, &ip);

//   if (!map_table) {
//     bpf_debug("MAC Address NOT Found for IP addr: 0x%x", ip);
//     return 1;
//   }

//   memcpy(p_eth->h_dest, map_table->mac_address, sizeof(p_eth->h_dest));

//   return 0;
// }

/*****************************************************************************************************************/
// static u32 get_ip_address_from_map(e_reference_point key) {
//   struct s_interface* map_element =
//       bpf_map_lookup_elem(&m_upf_interfaces, &key);

//   if (map_element) {
//     // bpf_debug(
//     //     "Map Values: IP:0x%x, port:%d", map_element->ipv4_address,
//     //     map_element->port);
//     return map_element->ipv4_address;
//   }

//   bpf_debug("No IP address was found in the map, Drop the packet");
//   return XDP_DROP;
// }

/*****************************************************************************************************************/
// static u8* get_mac_address_from_map(e_reference_point key) {
//   struct s_interface* map_element =
//       bpf_map_lookup_elem(&m_upf_interfaces, &key);

//   if (map_element) {
//     return map_element->mac_address;
//   }

//   bpf_debug("No MAC address was found in the map");
// }

/*****************************************************************************************************************/
inline static u32 create_outer_header_gtpu_ipv4(
    struct xdp_md* p_ctx, pfcp_far_t_* p_far) {
  // bpf_debug("Create Outer Header GTPU_IPv4");
  // bpf_debug("Original Packet: Data/UDP/IP/ETH");

  // Adjust space to the left.
  if (bpf_xdp_adjust_head(p_ctx, (int32_t) -GTP_ENCAPSULATED_SIZE)) {
    return XDP_DROP;
  }

  void* p_data     = (void*) (long) p_ctx->data;
  void* p_data_end = (void*) (long) p_ctx->data_end;

  e_reference_point key = N3_INTERFACE;

  struct s_interface* map_element =
      bpf_map_lookup_elem(&m_upf_interfaces, &key);

  if (!map_element) {
    bpf_debug("No IP address was found in the map, Drop the packet");
    return XDP_DROP;
  }

  u32 n3_ip = map_element->ipv4_address;

  /*
  |----------------------------------------------------------------|
  |----------------------- Update ETH header ----------------------|
  |----------------------------------------------------------------|
  */
  struct ethhdr* p_eth = p_data;
  if ((void*) (p_eth + 1) > p_data_end) {
    bpf_debug("Invalid pointer");
    return XDP_DROP;
  }

  struct ethhdr* p_orig_eth = p_data + GTP_ENCAPSULATED_SIZE;

  if ((void*) (p_orig_eth + 1) > p_data_end) {
    bpf_debug("Invalid Pointer");
    return XDP_DROP;
  }
  __builtin_memcpy(p_eth, p_orig_eth, sizeof(*p_eth));

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add IP header -----------------------|
  |----------------------------------------------------------------|
  */
  struct iphdr* p_ip = (void*) (p_eth + 1);
  if ((void*) (p_ip + 1) > p_data_end) {
    return XDP_DROP;
  }

  struct iphdr* p_inner_ip = (void*) p_ip + GTP_ENCAPSULATED_SIZE;
  if ((void*) (p_inner_ip + 1) > p_data_end) {
    return XDP_DROP;
  }

  p_ip->version = 4;
  p_ip->ihl     = 5;  // No options
  p_ip->tos     = 0;
  p_ip->tot_len = ntohs(p_inner_ip->tot_len) +
                  GTP_ENCAPSULATED_SIZE;  // htons(ntohs(p_inner_ip->tot_len) +
                                          // GTP_ENCAPSULATED_SIZE);
  p_ip->id       = 0;       // No fragmentation
  p_ip->frag_off = 0x0040;  // Don't fragment; Fragment offset = 0
  p_ip->ttl      = 64;
  p_ip->protocol = IPPROTO_UDP;
  p_ip->check    = 0;
  p_ip->saddr    = n3_ip;
  p_ip->daddr =
      p_far->forwarding_parameters.outer_header_creation.ipv4_address.s_addr;

  // bpf_debug("IP SRC: 0x%x, IP DST: 0x%x", p_ip->saddr, p_ip->daddr);

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add UDP header ----------------------|
  |----------------------------------------------------------------|
  */
  struct udphdr* p_udp = (void*) (p_ip + 1);
  if ((void*) (p_udp + 1) > p_data_end) {
    return XDP_DROP;
  }

  p_udp->source = GTP_UDP_PORT;  // htons(GTP_UDP_PORT);
  p_udp->dest   = GTP_UDP_PORT;  // htons(GTP_UDP_PORT);
  // htons(p_far->forwarding_parameters.outer_header_creation.port_number);
  p_udp->len = ntohs(p_inner_ip->tot_len) + sizeof(*p_udp) +
               sizeof(struct gtpuhdr) +
               sizeof(struct gtpu_extn_pdu_session_container);
  /*
   * htons(
   * ntohs(p_inner_ip->tot_len) + sizeof(*p_udp) + sizeof(struct gtpuhdr) +
   * sizeof(struct gtpu_extn_pdu_session_container));
   */

  p_udp->check = 0;

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add GTP header ----------------------|
  |----------------------------------------------------------------|
  */
  // struct s_interface* map_element = bpf_map_lookup_elem(&m_upf_interfaces,
  // &key);

  // if (!map_element) {
  //   bpf_debug("UPF N3 MAC address not found!!");
  //   return XDP_DROP;
  // }

  void* n3_mac              = map_element->mac_address;
  struct s_arp_mapping* map = bpf_map_lookup_elem(&m_arp_table, &n3_ip);
  void* p_mac_address       = map->mac_address;
  if (!p_mac_address) {
    bpf_debug("MAC address not found!!");
    return XDP_DROP;
  }

  // swap_src_dst_mac(p_data);
  __builtin_memcpy(p_eth->h_dest, p_mac_address, sizeof(p_eth->h_dest));
  __builtin_memcpy(p_eth->h_source, n3_mac, sizeof(p_eth->h_source));

  struct gtpuhdr* p_gtpuh = (void*) (p_udp + 1);
  if ((void*) (p_gtpuh + 1) > p_data_end) {
    return XDP_DROP;
  }

  u8 flags = GTP_EXT_FLAGS;
  __builtin_memcpy(p_gtpuh, &flags, sizeof(u8));
  p_gtpuh->message_type   = GTPU_G_PDU;
  p_gtpuh->message_length = ntohs(p_inner_ip->tot_len) +
                            sizeof(struct gtpu_extn_pdu_session_container) + 4;
  // htons(ntohs(p_inner_ip->tot_len) + sizeof(struct
  // gtpu_extn_pdu_session_container) + 4);
  p_gtpuh->teid = p_far->forwarding_parameters.outer_header_creation.teid;
  // htobe32(p_far->forwarding_parameters.outer_header_creation.teid);
  // bpf_debug(
  // "TEID from p_far:0x%x",
  // p_far->forwarding_parameters.outer_header_creation.teid);
  p_gtpuh->sequence      = GTP_SEQ;
  p_gtpuh->pdu_number    = GTP_PDU_NUMBER;
  p_gtpuh->next_ext_type = GTP_NEXT_EXT_TYPE;

  /*
  |----------------------------------------------------------------|
  |-------------------- Add GTP extension header ------------------|
  |----------------------------------------------------------------|
  */
  struct gtpu_extn_pdu_session_container* p_gtpu_ext_h = (void*) (p_gtpuh + 1);
  if ((void*) (p_gtpu_ext_h + 1) > p_data_end) {
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
  // __wsum l3sum = pcn_csum_diff(0, 0, (__be32*) p_ip, sizeof(*p_ip), 0);
  // int ret      = pcn_l3_csum_replace(p_ctx, IP_CSUM_OFFSET, 0, l3sum, 0);

  // if (ret) {
  //   bpf_debug("Checksum Calculation Error %d\n", ret);
  // }
  return 0;
}

/*****************************************************************************************************************/
/**
 * @brief Apply forwarding action rules.
 *
 * @param p_gtpuh The GTPU header.
 * @param p_session The session of this context.
 * @return u32 XDP action.
 */

// static u32 pfcp_far_apply(struct xdp_md* p_ctx, pfcp_far_t_* p_far) {
//   void* p_data         = (void*) (long) p_ctx->data;
//   void* p_data_end     = (void*) (long) p_ctx->data_end;
//   struct ethhdr* p_eth = p_data;

//   if ((void*) (p_eth + 1) > p_data_end) {
//     bpf_debug("Invalid pointer");
//     return XDP_DROP;
//   }

//   // Check if it is a forward action.
//   if (!p_far) {
//     bpf_debug("Invalid FAR!");
//     return XDP_DROP;
//   }

//   u8 dest_interface =
//       p_far->forwarding_parameters.destination_interface.interface_value;

//   u16 outer_header_creation =
//   p_far->forwarding_parameters.outer_header_creation
//                                   .outer_header_creation_description;

//   // Check forwarding action
//   if (!p_far->apply_action.forw) {
//     bpf_debug("Forward Action Is NOT set");
//     return XDP_PASS;
//   }

//   if (dest_interface == INTERFACE_VALUE_CORE) {
//     // Redirect to data network.
//     bpf_debug("Destination is to INTERFACE_VALUE_CORE");
//     bpf_debug("GTP Header Removal ...");
//     struct ethhdr* p_new_eth = p_data + GTP_ENCAPSULATED_SIZE;

//     if ((void*) (p_new_eth + 1) > p_data_end) {
//       return XDP_DROP;
//     }

//     __builtin_memcpy(p_new_eth, p_eth, sizeof(*p_eth));

//     // Adjust head to the right.
//     if (bpf_xdp_adjust_head(p_ctx, GTP_ENCAPSULATED_SIZE)) {
//       return XDP_DROP;
//     }

//     return bpf_redirect_map(&m_redirect_interfaces, UPLINK, 0);

//     bpf_debug("OUTER_HEADER_CREATION_UDP_IPV4 REDIRECT FAILED");
//   } else if (dest_interface == INTERFACE_VALUE_ACCESS) {
//       create_outer_header_gtpu_ipv4(p_ctx, p_far);
//       int ifindex = 3;
//       return bpf_redirect(ifindex, 0);
//       // return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
//   }
// }

/*****************************************************************************************************************/
SEC("xdp_far")
int far_entry_point(struct xdp_md* p_ctx) {
  u32 key            = 0;
  pfcp_far_t_* p_far = bpf_map_lookup_elem(&m_far, &key);

  if (p_far) {
    // return pfcp_far_apply(p_ctx, p_far);
    void* p_data         = (void*) (long) p_ctx->data;
    void* p_data_end     = (void*) (long) p_ctx->data_end;
    struct ethhdr* p_eth = p_data;

    if ((void*) (p_eth + 1) > p_data_end) {
      bpf_debug("Invalid pointer");
      return XDP_DROP;
    }

    // Check if it is a forward action.
    if (!p_far) {
      bpf_debug("Invalid FAR!");
      return XDP_DROP;
    }

    u8 dest_interface =
        p_far->forwarding_parameters.destination_interface.interface_value;

    u16 outer_header_creation =
        p_far->forwarding_parameters.outer_header_creation
            .outer_header_creation_description;

    // Check forwarding action
    if (!p_far->apply_action.forw) {
      bpf_debug("Forward Action Is NOT set");
      return XDP_PASS;
    }

    if (dest_interface == INTERFACE_VALUE_CORE) {
      // Redirect to data network.
      // bpf_debug("Destination is to INTERFACE_VALUE_CORE");
      // bpf_debug("GTP Header Removal ...");
      struct ethhdr* p_new_eth = p_data + GTP_ENCAPSULATED_SIZE;

      if ((void*) (p_new_eth + 1) > p_data_end) {
        return XDP_DROP;
      }

      __builtin_memcpy(p_new_eth, p_eth, sizeof(*p_eth));

      // Adjust head to the right.
      if (bpf_xdp_adjust_head(p_ctx, GTP_ENCAPSULATED_SIZE)) {
        return XDP_DROP;
      }

      return bpf_redirect_map(&m_redirect_interfaces, UPLINK, 0);

      bpf_debug("OUTER_HEADER_CREATION_UDP_IPV4 REDIRECT FAILED");
    } else if (dest_interface == INTERFACE_VALUE_ACCESS) {
      if (!create_outer_header_gtpu_ipv4(p_ctx, p_far))
        return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
    }
  }

  bpf_debug("FAR Program NOT Found!");
  return XDP_DROP;

  // TODO - DONWLINK UPLINK LOGICx`
}

char _license[] SEC("license") = "GPL";
/*****************************************************************************************************************/
