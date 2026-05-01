/**
 * @file upf_xdp_kern.c
 * @brief UPF (User Plane Function) XDP datapath kernel program
 *
 * This program implements the 5G UPF datapath using XDP (eXpress Data Path)
 * for high-performance packet processing. It handles:
 *
 * Traffic Flows:
 * - Uplink (N3→N6): GTP-U decapsulation, session lookup, forwarding to data
 * network
 * - Downlink (N6→N3): Session lookup, GTP-U encapsulation, forwarding to RAN
 * - QoS Shaping: Metadata preparation for TC (Traffic Control) layer
 *
 * Key Operations:
 * - PFCP session management and lookup
 * - PDR (Packet Detection Rule) matching with precedence
 * - FAR (Forwarding Action Rule) application
 * - SDF (Service Data Flow) filtering
 * - GTP-U tunnel encapsulation/decapsulation
 * - QoS flow classification
 *
 * Architecture:
 * ```
 * N3 (RAN) ←→ [XDP: uplink/downlink] ←→ N6 (Data Network)
 *                      ↓
 *                  [TC Layer]
 *                  (QoS Shaping)
 * ```
 *
 * @see 3GPP TS 23.501 - 5G System Architecture
 * @see 3GPP TS 29.244 - PFCP Protocol
 * @see 3GPP TS 29.281 - GTP-U Protocol
 *
 * @copyright 2024 OpenAirInterface
 * @license GPL-2.0
 */

#define KBUILD_MODNAME upf_xdp_kern

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/in.h>
//#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <stdbool.h>
#include <string.h>
#include <endian.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "linux/custom_types.h"

/* Utilities */
#include "utils/csum.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"
#include "utils/types.h"

/* Protocols */
#include "protocols/gtpu.h"

/* PFCP structures */
#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_pdr.h"
#include "ie/group_ie/pdi.h"

/* Maps and definitions */
#include "upf_xdp_maps.h"
#include "interfaces.h"
#include "sdf_filter.h"
#include "framed_routing_bpf.h"
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

#define IP_DF 0x4000 /* Don't fragment; Fragment offset = 0 */
/* ========================================================================== */
/*                          GLOBAL CACHE VARIABLES                            */
/* ========================================================================== */

/**
 * @brief Cached UPF interface IP addresses
 *
 * These are loaded once from BPF maps and cached for performance.
 * Reduces map lookups in the hot path.
 */
static u32 cached_n3_ip = 0;
static u32 cached_n6_ip = 0;

/**
 * @brief Cached MAC addresses for next-hop routing
 */
// static u8 cached_n3_next_hop_mac[ETH_ALEN] = {0};
// static u8 cached_n6_next_hop_mac[ETH_ALEN] = {0};

/**
 * @brief Cache validity flags
 *
 * Indicate whether the cached values are valid.
 * Set to false on program load, true after first lookup.
 */
static bool n3_cache_valid = false;
static bool n6_cache_valid = false;

// static u32 upf_n3_ip = 0;
// static u32 upf_n6_ip = 0;

// static u8 next_hop_n3_mac_address[6] = {0};
// // static u8 next_hop_n6_mac_address[6] = {0};

// static bool n3_cache_valid = false;
// // static bool cached_n6 = false;

// //#define MAX_PDRS_PER_SESSION 32

/*
 * NOTE: Next-hop MAC is NOT cached anymore.
 * It must be looked up per-packet using the per-session peer IP from FAR,
 * because a UPF may talk to several gNBs (one per session).
 */
/* ========================================================================== */
/*                              VLAN SUPPORT                                  */
/* ========================================================================== */

/**
 * @brief VLAN header structure
 *
 * Used for VLAN-tagged traffic processing.
 * Currently not actively used but reserved for future VLAN support.
 */
struct vlan_hdr {
  __be16 tci; /**< TCI (Tag Control Information): Priority + VLAN ID */
  __be16 encapsulated_proto; /**< Encapsulated protocol (e.g., ETH_P_IP) */
} __attribute__((packed));

/* ========================================================================== */
/*                          MAC ADDRESS MANAGEMENT                            */
/* ========================================================================== */

/**
 * @brief Update destination MAC address from ARP table
 *
 * Looks up the MAC address for a given IP and updates the Ethernet
 * destination field. Used before packet forwarding.
 *
 * @param ip Target IPv4 address (network byte order)
 * @param eth Ethernet header to update
 * @return true if MAC found and updated, false otherwise
 *
 * Example:
 * ```c
 * if (!update_dst_mac(next_hop_ip, eth)) {
 *     bpf_debug("MAC not found for IP: %pI4", &next_hop_ip);
 * }
 * ```
 */
static __always_inline bool update_dst_mac(u32 ip, struct ethhdr* eth) {
  struct arp_entry* arp = {0};

  if (!eth) {
    return false;
  }

  arp = bpf_map_lookup_elem(&arp_table_map, &ip);
  if (!arp) {
    bpf_debug("ARP lookup failed for %pI4", &ip);
    return false;
  }

  __builtin_memcpy(eth->h_dest, arp->mac_address, ETH_ALEN);

  return true;
}

/* ========================================================================== */
/*                          SDF FILTER MATCHING                               */
/* ========================================================================== */

/**
 * @brief Match packet 5-tuple against SDF filter
 *
 * Performs comprehensive packet matching based on:
 * - IP protocol (TCP, UDP, ICMP, or wildcard)
 * - Source IP and subnet mask
 * - Destination IP and subnet mask
 * - Source port range
 * - Destination port range
 *
 * @param pkt_filter Packet 5-tuple extracted from headers
 * @param sdf Service Data Flow filter rules
 * @return 1 if match, 0 if no match
 *
 * Match logic:
 * - Protocol: 0 = any, otherwise must match exactly
 * - IPs: (packet_ip & mask) must equal (sdf_ip & mask)
 * - Ports: packet_port must be within [lower_bound, upper_bound]
 */
static __always_inline u32 match_sdf_filter(
    const struct packet_filter* pkt_filter, const struct sdf_filtr* sdf) {
  u8 pkt_proto     = pkt_filter->protocol;
  u16 pkt_src_port = pkt_filter->src_port;
  u16 pkt_dst_port = pkt_filter->dst_port;
  u32 pkt_src_ip   = bpf_htonl(pkt_filter->src_ip);
  u32 pkt_dst_ip   = bpf_htonl(pkt_filter->dst_ip);

  u32 sdf_src_ip   = bpf_htonl((u32) (sdf->src_addr.ip));
  u32 sdf_dst_ip   = bpf_htonl((u32) (sdf->dst_addr.ip));
  u32 sdf_src_mask = bpf_htonl((u32) (sdf->src_addr.mask >> 96));
  u32 sdf_dst_mask = bpf_htonl((u32) (sdf->dst_addr.mask >> 96));

  bpf_debug(" Standard IANA-assigned IP protocol numbers:");

  bpf_debug("{ip, 0}, {icmp, 1}, {tcp, 6}, {udp, 17}, {icmp6, 58}");

  bpf_debug(
      "( sdf_protocol, packet_protocol ) : ( %u, %u )", sdf->protocol,
      pkt_proto);

  bpf_debug(
      "( sdf_saddr/mask,  packet_saddr ) : ( %pI4/%pI4, %pI4 )", &sdf_src_ip,
      &sdf_dst_mask, &pkt_src_ip);

  bpf_debug(
      "( sdf_daddr/mask,  packet_daddr ) : ( %pI4/%pI4, %pI4 )", &sdf_dst_ip,
      &sdf_dst_mask, &pkt_dst_ip);

  bpf_debug(
      "( (sdf_sport_lower, sdf_sport_upper), packet_sport ) : ( (%u, %u), %u "
      ")",
      sdf->src_port.lower_bound, sdf->src_port.upper_bound, pkt_src_port);

  bpf_debug(
      "( (sdf_dport_lower, sdf_dport_upper), packet_dport ) : ( (%u, %u), %u "
      ")",
      sdf->dst_port.lower_bound, sdf->dst_port.upper_bound, pkt_dst_port);

  if (/* Match protocol (0 = any protocol) */
      ((sdf->protocol == 0) || (pkt_proto == sdf->protocol)) &&
      /* Match source IP with subnet mask */
      ((pkt_src_ip & sdf_src_mask) == sdf_src_ip) &&
      /* Match destination IP with subnet mask */
      ((pkt_dst_ip & sdf_dst_mask) == sdf_dst_ip) &&
      /* Match source port range */
      ((pkt_src_port >= sdf->src_port.lower_bound) &&
       (pkt_src_port <= sdf->src_port.upper_bound)) &&
      /* Match destination port range */
      ((pkt_dst_port >= sdf->dst_port.lower_bound) &&
       (pkt_dst_port <= sdf->dst_port.upper_bound))) {
    bpf_debug("SDF filter matched");
    return 1;
  }
  bpf_debug("SDF filter not matched");
  return 0;
}

/* ========================================================================== */
/*                      GTP-U ENCAPSULATION (DOWNLINK)                        */
/* ========================================================================== */

/**
 * @brief Create GTP-U outer headers for downlink packets
 *
 * Adds complete GTP-U tunnel encapsulation:
 * - Outer Ethernet header (copied from inner, MAC updated)
 * - Outer IP header (UPF N3 IP → RAN IP)
 * - Outer UDP header (port 2152)
 * - GTP-U header (with TEID from FAR)
 * - GTP-U extension: PDU Session Container (with QFI)
 *
 * Packet transformation:
 * Before: [ETH][IP][UDP/TCP][DATA]
 * After:  [ETH][IP-outer][UDP-outer][GTP-U][GTP-Ext][ETH][IP][UDP/TCP][DATA]
 *
 * @param ctx XDP context
 * @param far Forwarding Action Rule with encapsulation parameters
 * @param qfi QoS Flow Identifier for GTP-U extension
 * @return RET_SUCCESS, RET_DROP, or RET_FAILURE
 */

static __always_inline u32
gtpu_encap_ipv4(struct xdp_md* ctx, struct pfcp_far* far, u8 qfi) {
  /* Expand headroom for GTP-U encapsulation */
  if (bpf_xdp_adjust_head(ctx, (int32_t) -GTP_ENCAPSULATED_SIZE)) {
    bpf_debug("Failed to adjust head for GTP-U encap");
    return RET_DROP;
  }

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  /* Get next-hop MAC for N3 */
  // if (!n3_cache_valid) {
  //   // Retrieve N3 interface configuration
  //   reference_point_t iface_key = N3_INTERFACE;
  //   struct interface_config* iface =
  //       bpf_map_lookup_elem(&upf_interface_map, &iface_key);

  //   if (!iface) {
  //     bpf_debug("N3 interface not configured");
  //     return RET_FAILURE;
  //   }

  //   cached_n3_ip   = iface->ipv4_address;
  //   n3_cache_valid = true;

  //   struct arp_entry* arp = {0};
  //   arp                   = bpf_map_lookup_elem(&arp_table_map,
  //   &cached_n3_ip);

  //   if (!arp) {
  //     bpf_debug("N3 next-hop MAC not found");
  //     return RET_FAILURE;
  //   }

  //   __builtin_memcpy(cached_n3_next_hop_mac, arp->mac_address, ETH_ALEN);
  // }

  /*
   * Per-session next-hop MAC resolution.
   * The peer IP (gNB) is taken from the FAR's outer header creation,
   * which is per-PDR/per-session. This guarantees that each session
   * is forwarded to its own gNB even when several gNBs are attached
   * to the UPF concurrently.
   */
  u32 peer_gnb_ip =
      far->forwarding_parameters.outer_header_creation.ipv4_address.s_addr;

  struct arp_entry* arp = bpf_map_lookup_elem(&arp_table_map, &peer_gnb_ip);

  if (!arp) {
    bpf_debug("N3 next-hop MAC not found for gNB %pI4", &peer_gnb_ip);
    return RET_FAILURE;
  }

  /* Cache the local N3 IP only (it is unique per UPF) */
  if (!n3_cache_valid) {
    reference_point_t iface_key = N3_INTERFACE;
    struct interface_config* iface =
        bpf_map_lookup_elem(&upf_interface_map, &iface_key);

    if (!iface) {
      bpf_debug("N3 interface not configured");
      return RET_FAILURE;
    }

    cached_n3_ip   = iface->ipv4_address;
    n3_cache_valid = true;
  }

  /*
  |----------------------------------------------------------------|
  |------------------ Build outer Ethernet header -----------------|
  |----------------------------------------------------------------|
  */
  struct ethhdr* eth_outer = data;
  if ((void*) (eth_outer + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return RET_DROP;
  }

  struct ethhdr* eth_inner = data + GTP_ENCAPSULATED_SIZE;
  if ((void*) (eth_inner + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet copy header");
    return RET_DROP;
  }

  /* Copy inner Ethernet header to outer position */
  __builtin_memcpy(eth_outer, eth_inner, sizeof(*eth_outer));

  /* Update destination MAC to N3 next-hop */
  //__builtin_memcpy(eth_outer->h_dest, cached_n3_next_hop_mac, ETH_ALEN);

  __builtin_memcpy(eth_outer->h_dest, arp->mac_address, ETH_ALEN);

  // bpf_debug(
  //     "Destination MAC:%x:%x:%x:", ethh->h_dest[0], ethh->h_dest[1],
  //     ethh->h_dest[2]);
  // bpf_debug("%x:%x:%x", ethh->h_dest[3], ethh->h_dest[4], ethh->h_dest[5]);

  /*
  |----------------------------------------------------------------|
  |--------------------- Build outer IP header --------------------|
  |----------------------------------------------------------------|
  */
  struct iphdr* ip_outer = (void*) (eth_outer + 1);
  if ((void*) (ip_outer + 1) > data_end) {
    bpf_debug("Error: Invalid outer IP header");
    return RET_DROP;
  }

  struct iphdr* ip_inner = (void*) ip_outer + GTP_ENCAPSULATED_SIZE;
  if ((void*) (ip_inner + 1) > data_end) {
    bpf_debug("Error: Invalid inner IP header");
    return RET_DROP;
  }

  ip_outer->version = 4;
  ip_outer->ihl     = 5; /* No options */
  ip_outer->tos     = 0; /* TODO: Copy from inner or map from QFI */
  ip_outer->tot_len =
      bpf_htons(bpf_ntohs(ip_inner->tot_len) + GTP_ENCAPSULATED_SIZE);
  ip_outer->id       = 0;                /* No fragmentation */
  ip_outer->frag_off = bpf_htons(IP_DF); /* Don't fragment */
  ip_outer->ttl      = 64;
  ip_outer->protocol = IPPROTO_UDP;
  ip_outer->check    = 0;
  ip_outer->saddr    = cached_n3_ip;
  ip_outer->daddr =
      far->forwarding_parameters.outer_header_creation.ipv4_address.s_addr;

  bpf_debug(
      "GTP-U encap: outer IP ( ip_saddr, ip_daddr ) : ( %pI4, %pI4 )",
      &ip_outer->saddr, &ip_outer->daddr);

  /*
  |----------------------------------------------------------------|
  |-------------------- Build outer UDP header --------------------|
  |----------------------------------------------------------------|
  */
  struct udphdr* udp_outer = (void*) (ip_outer + 1);
  if ((void*) (udp_outer + 1) > data_end) {
    bpf_debug("Error: Invalid outer UDP header");
    return RET_DROP;
  }

  udp_outer->source = bpf_htons(GTP_UDP_PORT);
  udp_outer->dest   = bpf_htons(GTP_UDP_PORT);
  // bpf_htons(far->forwarding_parameters.outer_header_creation.port_number);
  udp_outer->len = bpf_htons(
      bpf_ntohs(ip_inner->tot_len) + sizeof(*udp_outer) +
      sizeof(struct gtpuhdr) + sizeof(struct gtpu_extn_pdu_session_container));
  udp_outer->check = 0; /* UDP checksum optional for IPv4 */

  /*
  |----------------------------------------------------------------|
  |----------------------- Build GTP-U header ---------------------|
  |----------------------------------------------------------------|
  */
  struct gtpuhdr* gtpu = (void*) (udp_outer + 1);
  if ((void*) (gtpu + 1) > data_end) {
    bpf_debug("Error: Invalid GTP-U header");
    return RET_DROP;
  }

  u8 flags = GTP_EXT_FLAGS; /* Version=1, PT=1, E=1 */
  __builtin_memcpy(gtpu, &flags, sizeof(u8));
  gtpu->message_type   = GTPU_G_PDU;
  gtpu->message_length = bpf_htons(
      bpf_ntohs(ip_inner->tot_len) +
      sizeof(struct gtpu_extn_pdu_session_container) + 4);
  gtpu->teid = bpf_htonl(far->forwarding_parameters.outer_header_creation.teid);
  gtpu->sequence      = GTP_SEQ;
  gtpu->pdu_number    = GTP_PDU_NUMBER;
  gtpu->next_ext_type = GTP_NEXT_EXT_TYPE;

  bpf_debug("GTP-U TEID: 0x%x", bpf_ntohl(gtpu->teid));

  /*
  |----------------------------------------------------------------|
  |--------------- Build GTP-U extension header -------------------|
  |----------------------------------------------------------------|
  */
  struct gtpu_extn_pdu_session_container* gtpu_ext = (void*) (gtpu + 1);
  if ((void*) (gtpu_ext + 1) > data_end) {
    bpf_debug("Error: Invalid GTP-U extension header");
    return RET_DROP;
  }

  gtpu_ext->message_length = GTP_EXT_MSG_LEN;
  gtpu_ext->pdu_type       = GTP_EXT_PDU_TYPE;
  gtpu_ext->qfi            = qfi;  // GTP_DEFAULT_QFI;
  gtpu_ext->next_ext_type  = GTP_EXT_NEXT_EXT_TYPE;

  /*
  |----------------------------------------------------------------|
  |---------------- Calculate outer IP checksum -------------------|
  |----------------------------------------------------------------|
  */
  __wsum csum = pcn_csum_diff(0, 0, (__be32*) ip_outer, sizeof(*ip_outer), 0);
  int ret     = pcn_l3_csum_replace(ctx, IP_CSUM_OFFSET, 0, csum, 0);

  if (ret) {
    bpf_debug("Error: Invalid Checksum Calculation %d", ret);
  }

  bpf_debug("GTP-U encapsulation complete");
  return RET_SUCCESS;
}

/* ========================================================================== */
/*                      GTP-U DECAPSULATION (UPLINK)                          */
/* ========================================================================== */

/**
 * @brief Remove GTP-U outer headers from uplink packets
 *
 * Strips the GTP-U tunnel encapsulation:
 * - Removes outer IP, UDP, GTP-U headers
 * - Copies inner Ethernet header to outer position
 * - Updates destination MAC for N6 forwarding
 *
 * Packet transformation:
 * Before: [ETH][IP-outer][UDP-outer][GTP-U][GTP-Ext][ETH][IP][UDP/TCP][DATA]
 * After:  [ETH][IP][UDP/TCP][DATA]
 *
 * @param ctx XDP context
 * @param far Forwarding Action Rule (must have FORW flag set)
 * @return RET_SUCCESS, RET_DROP, or RET_FAILURE
 */

static __always_inline u32
gtpu_decap_ipv4(struct xdp_md* ctx, struct pfcp_far* far) {
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  struct ethhdr* eth_outer = data;
  if ((void*) (eth_outer + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return RET_DROP;
  }

  /* Verify FAR has forward action */
  if (!far->apply_action.forw) {
    bpf_debug("FAR forward action not set");
    return RET_FAILURE;
  }

  bpf_debug("GTP-U decapsulation in progress");

  /* Get inner ethernet header position */
  struct ethhdr* eth_inner = (void*) (data + GTP_ENCAPSULATED_SIZE);

  if ((void*) (eth_inner + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet copy header");
    return RET_DROP;
  }

  /* Copy outer ethernet to inner position */
  __builtin_memcpy(eth_inner, eth_outer, sizeof(*eth_inner));

  /* Get next-hop MAC for N6 */
  // if (!n6_cache_valid) {
  //   /* Retrieve N6 interface configuration */
  //   reference_point_t iface_key = N6_INTERFACE;
  //   struct interface_config* iface =
  //       bpf_map_lookup_elem(&upf_interface_map, &iface_key);

  //   if (!iface) {
  //     bpf_debug("N6 interface not configured");
  //     return RET_FAILURE;
  //   }

  //   cached_n6_ip   = iface->ipv4_address;
  //   n6_cache_valid = true;

  //   struct arp_entry* arp = {0};
  //   arp                   = bpf_map_lookup_elem(&arp_table_map,
  //   &cached_n6_ip);

  //   if (!arp) {
  //     bpf_debug("N6 next-hop MAC not found");
  //     return RET_FAILURE;
  //   }

  //   __builtin_memcpy(cached_n6_next_hop_mac, arp->mac_address, ETH_ALEN);
  // }

  // /* Update destination MAC */
  // memcpy(eth_inner->h_dest, cached_n6_next_hop_mac,
  // sizeof(eth_inner->h_dest));

  /*
   * Per-session next-hop MAC resolution for N6.
   * NOTE: For uplink, the N6 next-hop is typically a single gateway
   * (DN ingress router), so the previous global cache happened to work.
   * However, in deployments with multiple DNs (multiple DNNs), the
   * next-hop varies per session. We therefore do a per-packet lookup
   * keyed by the FAR's outer-header creation IP if present, falling
   * back to the cached N6 IP otherwise.
   *
   * IMPORTANT: For uplink decapsulation, the FAR may not carry an
   * outer-header creation (the packet is being de-encapsulated, not
   * encapsulated), so we use a per-DN routing key. For now, we keep
   * keying on the N6 local IP — this is a known limitation that should
   * be addressed when multi-DN support is added.
   */
  if (!n6_cache_valid) {
    reference_point_t iface_key = N6_INTERFACE;
    struct interface_config* iface =
        bpf_map_lookup_elem(&upf_interface_map, &iface_key);

    if (!iface) {
      bpf_debug("N6 interface not configured");
      return RET_FAILURE;
    }

    cached_n6_ip   = iface->ipv4_address;
    n6_cache_valid = true;
  }

  /*
   * Resolve N6 next-hop MAC.
   * In single-DN deployments this resolves the gateway towards the DN.
   * The userspace populates arp_table_map with key = N6 gateway IP
   * (NOT the local N6 IP).
   */
  /* TODO: replace cached_n6_ip with FAR-provided next-hop IP for
   * multi-DN deployments. */
  struct arp_entry* arp = bpf_map_lookup_elem(&arp_table_map, &cached_n6_ip);

  if (!arp) {
    bpf_debug("N6 next-hop MAC not found");
    return RET_FAILURE;
  }

  memcpy(eth_inner->h_dest, arp->mac_address, ETH_ALEN);

  bpf_debug("Dst MAC: %pM", eth_inner->h_dest);
  // bpf_debug(
  //     "Destination MAC  %x:%x:%x:", new_ethh->h_dest[0], new_ethh->h_dest[1],
  //     new_ethh->h_dest[2]);
  // bpf_debug(
  //     " %x:%x:%x", new_ethh->h_dest[3], new_ethh->h_dest[4],
  //     new_ethh->h_dest[5]);

  /* Remove GTP-U encapsulation by adjusting head */
  if (bpf_xdp_adjust_head(ctx, GTP_ENCAPSULATED_SIZE)) {
    bpf_debug("Error: Failed to adjust head for GTP-U decap");
    return RET_DROP;
  }

  bpf_debug("Outer header has been removed");

  bpf_debug("GTP-U decapsulation complete");
  return RET_SUCCESS;
}

/* ========================================================================== */
/*                        PACKET FILTER EXTRACTION                            */
/* ========================================================================== */

/**
 * @brief Extract 5-tuple from IP packet
 *
 * Extracts packet classification information:
 * - Source and destination IP addresses
 * - IP protocol
 * - Source and destination ports (for TCP/UDP)
 *
 * @param data Pointer to packet data
 * @param data_end Pointer to end of packet
 * @param ip IP header
 * @param pkt_filter_out Output: extracted packet filter
 * @return RET_SUCCESS or RET_FAILURE
 */
static __always_inline int extract_pkt_filter(
    void* data, void* data_end, struct iphdr* ip,
    struct packet_filter* pkt_filter_out) {
  if (!ip) {
    return RET_FAILURE;
  }

  u8 protocol              = ip->protocol;
  pkt_filter_out->src_ip   = bpf_ntohl(ip->saddr);
  pkt_filter_out->dst_ip   = bpf_ntohl(ip->daddr);
  pkt_filter_out->protocol = protocol;

  /* Extract ports for TCP/UDP */
  switch (protocol) {
    case IPPROTO_TCP: {
      struct tcphdr* tcp = (struct tcphdr*) (ip + 1);
      if ((void*) (tcp + 1) > data_end) {
        bpf_debug("Error: Invalid TCP header");
        return RET_FAILURE;
      }

      pkt_filter_out->src_port = bpf_ntohs(tcp->source);
      pkt_filter_out->dst_port = bpf_ntohs(tcp->dest);
      break;
    }
    case IPPROTO_UDP: {
      struct udphdr* udp = (struct udphdr*) (ip + 1);
      if ((void*) (udp + 1) > data_end) {
        bpf_debug("Error: Invalid UDP header");
        return RET_FAILURE;
      }

      pkt_filter_out->src_port = bpf_ntohs(udp->source);
      pkt_filter_out->dst_port = bpf_ntohs(udp->dest);
      break;
    }
    default:
      /* Non-TCP/UDP protocols don't have ports */
      bpf_debug(
          "Non-TCP/UDP protocols don't have ports. Use best effort QoS flow "
          "(i.e. default qfi)");
      pkt_filter_out->src_port = 0;
      pkt_filter_out->dst_port = 0;
      break;
  }

  return RET_SUCCESS;
}

/* ========================================================================== */
/*                        SESSION LOOKUP - UPLINK (N3)                        */
/* ========================================================================== */

/**
 * @brief Lookup PFCP session for uplink (N3→N6) traffic
 *
 * For GTP-U encapsulated packets from RAN:
 * 1. Extract TEID from GTP-U header (for PDR matching)
 * 2. Extract inner IP (UE IP is source)
 * 3. Lookup session by UE IP
 * 4. Extract QFI from GTP-U extension
 *
 * IMPORTANT: This function now also extracts the packet's TEID which is
 * needed for proper PDR matching per 3GPP TS 29.244.
 *
 * @param data Pointer to packet data
 * @param data_end Pointer to end of packet
 * @param eth Ethernet header
 * @param ue_ip_out Output: UE IP address
 * @param qfi_out Output: QFI from GTP-U extension
 * @param pkt_teid_out Output: TEID from incoming GTP-U packet (network byte
 * order)
 * @return Pointer to session_id or NULL
 */
static __always_inline struct session_id* lookup_session_n3(
    void* data, void* data_end, struct ethhdr* eth, u32* ue_ip_out, u8* qfi_out,
    u32* pkt_teid_out) {
  if (!eth) {
    return NULL;
  }

  u16 l3_protocol = bpf_htons(eth->h_proto);
  bpf_debug("Debug: l3_protocol:0x%x", l3_protocol);

  switch (l3_protocol) {
    case ETH_P_IP: {
      struct iphdr* ip_outer = (void*) (eth + 1);
      if ((void*) (ip_outer + 1) > data_end) {
        bpf_debug("Error: Invalid IPv4 header");
        return NULL;
      }

      struct udphdr* udp_outer = (void*) (ip_outer + 1);
      if ((void*) (udp_outer + 1) > data_end) {
        bpf_debug("Error: Invalid UDP header");
        return NULL;
      }

      if (bpf_htons(udp_outer->dest) != GTP_UDP_PORT) {
        bpf_debug("Error: Invalid GTP Port");
        return NULL;
      }

      bpf_debug("Identified Uplink GTP-U Traffic");

      struct gtpuhdr* gtpu = (void*) (udp_outer + 1);
      if ((void*) (gtpu + 1) > data_end) {
        bpf_debug("Error: Invalid GTP-U header");
        return NULL;
      }

      if (gtpu->message_type != GTPU_G_PDU) {
        bpf_debug(
            "Message type 0x%x is not GTPU GPDU(0x%x)\n", gtpu->message_type,
            GTPU_G_PDU);
        return NULL;
      }

      /* Extract TEID from incoming GTP-U packet for PDR matching */
      *pkt_teid_out = bpf_htonl(gtpu->teid);

      /* Extract QFI from GTP-U extension if present */
      struct gtpu_extn_pdu_session_container* gtpu_ext = (void*) (gtpu + 1);

      if ((void*) (gtpu_ext + 1) > data_end) {
        bpf_debug("Error: Invalid GTPU Extension header");
        return NULL;
      }
      *qfi_out = gtpu_ext->qfi;

      struct iphdr* ip_inner = (void*) (gtpu_ext + 1);

      if ((void*) (ip_inner + 1) > data_end) {
        bpf_debug("Error: Invalid Inner IP header");
        return NULL;
      }

      /* UE IP is inner source for uplink */
      *ue_ip_out = bpf_htonl(ip_inner->saddr);

      /* Lookup session by UE IP */
      return bpf_map_lookup_elem(&session_by_ue_ip_map, ue_ip_out);
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

/* ========================================================================== */
/*                       SESSION LOOKUP - DOWNLINK (N6)                       */
/* ========================================================================== */

/**
 * @brief Lookup PFCP session for downlink (N6→N3) traffic
 *
 * For plain IP packets from data network:
 * 1. Extract IP headers
 * 2. UE IP is destination IP
 * 3. Lookup session by UE IP
 * 4. Extract packet 5-tuple for SDF matching
 *
 * @param data Pointer to packet data
 * @param data_end Pointer to end of packet
 * @param eth Ethernet header
 * @param ue_ip_out Output: UE IP address
 * @param filter_out Output: packet 5-tuple
 * @return Pointer to session_id or NULL
 */

static __always_inline struct session_id* lookup_session_n6(
    void* data, void* data_end, struct ethhdr* eth, u32* ue_ip_out,
    struct packet_filter* pkt_filter_out) {
  if (!eth) {
    return NULL;
  }

  u16 l3_protocol = bpf_htons(eth->h_proto);
  bpf_debug("Debug: l3_protocol:0x%x", l3_protocol);

  switch (l3_protocol) {
    case ETH_P_IP: {
      struct iphdr* ip = (void*) (eth + 1);
      if ((void*) (ip + 1) > data_end) {
        bpf_debug("Error: Invalid IPv4 header");
        return NULL;
      }

      /* UE IP is destination for downlink */
      *ue_ip_out = bpf_htonl(ip->daddr);

      struct session_id* session =
          bpf_map_lookup_elem(&session_by_ue_ip_map, ue_ip_out);

      // Check if the QoS enforcement is enabled:
      if (session) {
        u64 session_id = session->seid;
        if (bpf_map_lookup_elem(&session_qos_enabled_map, &session_id)) {
          /* Extract packet filter */
          if (extract_pkt_filter(data, data_end, ip, pkt_filter_out) !=
              RET_SUCCESS) {
            return NULL;
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

/* ========================================================================== */
/*                      PDR MATCHING - UPLINK (N3)                            */
/* ========================================================================== */

/**
 * @brief Find matching PDR with highest precedence for uplink
 *
 * Iterates through all PDRs for the session and finds the one that:
 * 1. Has N3 (ACCESS) as source interface
 * 2. Matches F-TEID if present
 * 3. Matches SDF filter if present
 * 4. Has the lowest precedence value (= highest priority)
 *
 * @param seid PFCP Session ID
 * @param teid TEID from GTP-U header
 * @param qfi_inout Input: QFI from GTP-U, Output: QFI from matched PDR
 * @param filter Packet 5-tuple for SDF matching
 * @return Pointer to matched PDR or NULL
 */

static __always_inline struct pfcp_pdr* match_pdr_n3(
    u64 seid, u32 pkt_teid, u32 pkt_ue_ip, u8 pkt_qfi) {
  struct pfcp_pdr(*pdrs)[MAX_PDRS_PER_PDU_SESSION] =
      bpf_map_lookup_elem(&pdrs_per_session_map, &seid);

  if (!pdrs) {
    bpf_debug("No PDRs found for SEID: %llu", seid);
    return NULL;
  }

  /* Iterate through PDRs */
  /*
   * The pragma unrol will be replace with:
   *
   *      int i;
   *      bpf_for(i, 0, MAX_PDRS_PER_PDU_SESSION) {
   *
   * This is supported on newer kernels (v6.3+), Clang >= 17, libbpf >= 1.3 or
   * so, Linux kernel headers >= 6.3
   */

#pragma clang loop unroll(full)
  for (int i = 0; i < MAX_PDRS_PER_PDU_SESSION_LIMIT; i++) {
    if (i >= MAX_PDRS_PER_PDU_SESSION) break;
    struct pfcp_pdr* pdr = &(*pdrs)[i];

    /* Skip invalid PDRs */
    if (pdr->pdr_id.rule_id == 0) {
      continue;
    }

    /* Retrieve PDI from PDR */
    struct pdi pdi = pdr->pdi;

    /* Retrieve UE IP from PDI */
    u32 ipaddr = bpf_htonl(pdi.ue_ip_address.ipv4_address.s_addr);

    /*
     * Check UE IP match ONLY if present in PDR
     * Per 3GPP TS 29.244: UE IP is OPTIONAL in PDI for uplink PDRs
     * Open5GS doesn't include UE IP in uplink PDRs - this is compliant
     */

    if ((ipaddr != 0) && (ipaddr != pkt_ue_ip)) {
      continue;
    }

    /* Check source interface (must be N3/ACCESS) */
    if (bpf_htonl(pdi.source_interface.interface_value) !=
        INTERFACE_VALUE_ACCESS) {
      continue;
    }

    /* Check F-TEID match if present */
    if ((pdi.fteid.teid != 0) && (pdi.fteid.teid != pkt_teid)) {
      continue;
    }

    /* Check QFI match if present */
    if ((pdi.qfi.qfi != 0) && (pdi.qfi.qfi != pkt_qfi)) {
      continue;
    }

    bpf_debug(
        "( packet_ue_ip,  pdi.ue_ip_address ) : ( %pI4, %pI4 )", &pkt_ue_ip,
        &ipaddr);
    bpf_debug(
        "( packet_teid,   pdi.fteid.teid    ) : ( %d  , %d )", pkt_teid,
        pdi.fteid.teid);
    bpf_debug(
        "( packet_qfi,    pdi.qfi.qfi       ) : ( %u  , %u )", pkt_qfi,
        pdi.qfi.qfi);
    return pdr;
  }

  // No match found
  return NULL;
}

/* ========================================================================== */
/*                      PDR MATCHING - DOWNLINK (N6)                          */
/* ========================================================================== */

/**
 * @brief Calculate SDF filter specificity score for PDR selection
 *
 * When multiple PDRs match a packet, this score helps select the most specific
 * rule. Higher scores indicate more specific matches. This prevents generic
 * "any protocol" rules (protocol=0) from shadowing specific protocol rules
 * (protocol=1 for ICMP, protocol=6 for TCP, etc.).
 *
 * Scoring factors (in importance order):
 * 1. Protocol specificity: Exact match (300) > Wildcard (100)
 * 2. IP subnet mask bits: More specific subnet = higher score
 * 3. Port range narrowness: Specific ports > Wide ranges
 *
 * Example:
 * - PDR with "permit ip from any to any" (protocol=0): Score ~100
 * - PDR with "permit icmp from any to 12.1.1.0/24" (protocol=1): Score ~324
 * → ICMP PDR wins despite having worse precedence
 *
 * @param sdf SDF filter to score
 * @param pkt_proto Packet's IP protocol number (1=ICMP, 6=TCP, 17=UDP, etc.)
 * @return Specificity score (higher = more specific)
 */
static __always_inline u32
calc_sdf_specificity(const struct sdf_filtr* sdf, u8 pkt_proto) {
  u32 score = 0;

  /* Protocol specificity (most important factor) */
  if (sdf->protocol == 0) {
    /* Protocol=0 means "any IP protocol" - least specific */
    score += 100;
  } else if (sdf->protocol == pkt_proto) {
    /* Exact protocol match - most specific */
    score += 300;
  } else {
    /* Protocol mismatch - should not happen if SDF matched, but handle
     * gracefully */
    score += 50;
  }

  /* IP address specificity - count set bits in subnet masks */
  u32 src_mask = (u32) (sdf->src_addr.mask >> 96); /* IPv4 is top 32 bits of
                                                      128-bit field */
  u32 dst_mask = (u32) (sdf->dst_addr.mask >> 96);

  /* Use builtin popcount for efficient bit counting */
  score += __builtin_popcount(src_mask); /* 0-32 bits */
  score += __builtin_popcount(dst_mask); /* 0-32 bits */

  /* Port range specificity - reward narrow ranges */
  u16 src_port_range = sdf->src_port.upper_bound - sdf->src_port.lower_bound;
  u16 dst_port_range = sdf->dst_port.upper_bound - sdf->dst_port.lower_bound;

  /* Scale down to prevent overwhelming protocol score */
  if (src_port_range < 65535) {
    score += (65535 - src_port_range) / 1000; /* 0-65 points */
  }
  if (dst_port_range < 65535) {
    score += (65535 - dst_port_range) / 1000; /* 0-65 points */
  }

  return score;
}

/**
 * @brief Find matching PDR with highest specificity for downlink
 *
 * Iterates through all PDRs for the session and finds the one that:
 * 1. Has N6 (CORE) as source interface
 * 2. Matches UE IP if present
 * 3. Matches SDF filter if present
 * 4. Has the lowest precedence value (= highest priority)
 *
 * @param seid PFCP Session ID
 * @param pkt_ue_ip UE IP address
 * @param qfi_out Output: QFI from matched PDR
 * @param pkt_filter Packet 5-tuple for SDF matching
 * @return Pointer to matched PDR or NULL
 */
static __always_inline struct pfcp_pdr* match_pdr_n6(
    u64 seid, u32 pkt_ue_ip, u8* qfi_out, struct packet_filter* pkt_filter) {
  struct pfcp_pdr(*pdrs)[MAX_PDRS_PER_PDU_SESSION] =
      bpf_map_lookup_elem(&pdrs_per_session_map, &seid);

  if (!pdrs) {
    bpf_debug("No PDRs found for SEID: %llu", seid);
    return NULL;
  }

  /* Variables for tracking best match */
  struct pfcp_pdr* best_pdr = NULL;
  u32 best_specificity      = 0;
  u32 best_precedence       = 0xFFFFFFFF;
  u8 best_qfi               = 0;

  /* Check if QoS enforcement is enabled for this session */
  u32* qos_flag    = bpf_map_lookup_elem(&session_qos_enabled_map, &seid);
  bool qos_enabled = (qos_flag != NULL);

  /* Iterate through ALL PDRs to find best match */
  /*
   * The pragma unrol will be replace with:
   *
   *      int i;
   *      bpf_for(i, 0, MAX_PDRS_PER_PDU_SESSION) {
   *
   * This is supported on newer kernels (v6.3+), Clang >= 17, libbpf >= 1.3 or
   * so, Linux kernel headers >= 6.3
   */

#pragma clang loop unroll(full)
  for (int i = 0; i < MAX_PDRS_PER_PDU_SESSION_LIMIT; i++) {
    if (i >= MAX_PDRS_PER_PDU_SESSION) break;
    struct pfcp_pdr* pdr = &(*pdrs)[i];

    /* Skip invalid PDRs */
    if (pdr->pdr_id.rule_id == 0) {
      continue;
    }

    /* Retrieve PDI from PDR */
    struct pdi pdi = pdr->pdi;

    /* Retrieve UE IP from PDI */
    u32 ipaddr = bpf_htonl(pdi.ue_ip_address.ipv4_address.s_addr);

    /* Check UE IP */
    /* TODO:
     * Check if this is correct
     * in case of framed_routing
     */
    if (ipaddr != pkt_ue_ip) {
      continue;
    }

    /* Only process downlink PDRs (source interface = CORE) */
    u32 source_interface = pdi.source_interface.interface_value;
    if (source_interface != INTERFACE_VALUE_CORE) {
      continue;
    }

    /* Log PDR candidate */
    // bpf_debug(
    //     "( packet_ue_ip, pdi.ue_ip_address ) : ( %pI4, %pI4 )", &pkt_ue_ip,
    //     &ipaddr);
    // bpf_debug(
    //     "pdi.source_interface.interface_value: %d",
    //     pdi.source_interface.interface_value);

    /* Get QFI from PDR */
    u8 pdr_qfi     = pdi.qfi.qfi;
    u32 precedence = pdr->precedence.precedence;

    /* If QoS is disabled, return first matching downlink PDR */
    if (!qos_enabled) {
      bpf_debug("QoS enforcement not enabled for Session %llu", seid);
      *qfi_out = pdr_qfi;
      return pdr;
    }

    /* QoS enabled - check SDF filter */
    struct session_qfi sdf_key = {0};
    sdf_key.seid               = seid;
    sdf_key.qfi                = pdr_qfi;

    const struct sdf_filtr* sdf =
        bpf_map_lookup_elem(&sdf_filters_map, &sdf_key);

    if (!sdf) {
      /* No SDF filter - this is default/non-GBR traffic */
      bpf_debug(
          "SDF Filter not found for QFI %u - treating as non-GBR", pdr_qfi);

      /* Only select this if we haven't found a better match yet */
      if (!best_pdr) {
        best_pdr        = pdr;
        best_precedence = precedence;
        best_qfi        = pdr_qfi;
        bpf_debug(
            "First match (no SDF): PDR %u (precedence=%u, QFI=%u)",
            pdr->pdr_id.rule_id, precedence, pdr_qfi);
      }
      continue;
    }

    /* Log SDF lookup */
    bpf_debug("SDF key ( seid, qfi ): ( %llu, %u )", sdf_key.seid, sdf_key.qfi);

    /* Check if this PDR's SDF filter matches the packet */
    if (!match_sdf_filter(pkt_filter, sdf)) {
      bpf_debug("SDF filter did not match for PDR %u", pdr->pdr_id.rule_id);
      continue;
    }

    /* SDF matched! Calculate specificity score */
    u32 specificity = calc_sdf_specificity(sdf, pkt_filter->protocol);

    bpf_debug("PDR %u Matched: ", pdr->pdr_id.rule_id);
    bpf_debug("   - Specificity = %u", specificity);
    bpf_debug("   - Precedence  = %u", precedence);
    bpf_debug("   - QFI         = %u", pdr_qfi);

    /* Determine if this is a better match than current best */
    bool is_better = false;

    if (!best_pdr) {
      /* First match */
      is_better = true;
    } else if (specificity > best_specificity) {
      /* Higher specificity wins */
      is_better = true;
      bpf_debug(
          "PDR %u has higher specificity (%u > %u)", pdr->pdr_id.rule_id,
          specificity, best_specificity);
    } else if (
        (specificity == best_specificity) && (precedence < best_precedence)) {
      /* Same specificity, use precedence (lower is better) */
      is_better = true;
      bpf_debug(
          "PDR %u has better precedence (%u < %u)", pdr->pdr_id.rule_id,
          precedence, best_precedence);
    }

    if (is_better) {
      best_pdr         = pdr;
      best_specificity = specificity;
      best_precedence  = precedence;
      best_qfi         = pdr_qfi;
      bpf_debug("New best match PDR %u: ", pdr->pdr_id.rule_id);
      bpf_debug("   - Specificity = %u", specificity);
      bpf_debug("   - Precedence  = %u", precedence);
      bpf_debug("   - QFI         = %u", pdr_qfi);
    }
  }

  if (best_pdr) {
    *qfi_out = best_qfi;
    bpf_debug("Selected PDR %u :", best_pdr->pdr_id.rule_id);
    bpf_debug("   - Specificity = %u", best_specificity);
    bpf_debug("   - Precedence  = %u", best_precedence);
    bpf_debug("   - QFI         = %u", best_qfi);
  }

  return best_pdr;
}

/* ========================================================================== */
/*                      FAR APPLICATION - UPLINK (N3)                         */
/* ========================================================================== */

/**
 * @brief Apply Forwarding Action Rule for uplink traffic
 *
 * Processes uplink packets based on FAR action flags. According to 3GPP
 * TS 29.244, Apply Action is a bit field where multiple flags can be set
 * simultaneously. Therefore, we use bitwise checks (if statements with &)
 * rather than switch, as switch requires exact value matches and cannot detect
 * individual bits.
 *
 * Action priority order:
 * 1. DROP - Highest priority, drop packet immediately
 * 2. FORWARD - Decapsulate GTP-U and forward to N6
 * 3. BUFFER - Not supported in XDP, drop packet
 * 4. NOTIFY_CP - Not supported in XDP
 * 5. DUPLICATE - Not supported in XDP
 *
 * @param ctx XDP context
 * @param pdr_key PDR key to lookup associated rules (contains pdr_id and seid)
 * @return RET_REDIRECT on success, RET_DROP to drop, RET_FAILURE on error
 */

static __always_inline u32
apply_far_n3(struct xdp_md* ctx, struct pdrs_per_session pdr_key) {
  struct rules_match_pdr* rules    = {0};
  __attribute__((unused)) u64 seid = pdr_key.seid;

  /* Lookup the rules associated with this PDR */
  rules = bpf_map_lookup_elem(&rules_match_pdr_map, &pdr_key);

  if (!rules) {
    bpf_debug("No rules found for PDR (seid=%llu)", seid);
    return RET_FAILURE;
  }

  /* Get FAR from rules */
  struct pfcp_far* far = &rules->far;

  if (!far || far->far_id.far_id == 0) {
    bpf_debug("Invalid FAR for session %llu", seid);
    return RET_FAILURE;
  }

  bpf_debug("Applying FAR ID=%u for session %llu", far->far_id.far_id, seid);

  /* Get action flags - the byte may contain multiple flags set */
  u8 action = *((u8*) &far->apply_action);

  /*
   * Check each flag using bitwise AND (&) operator
   * We cannot use switch here because Apply Action is a bit field.
   * Example: if action=0x0A (FORW + NOCP), switch(0x0A) won't match
   * case APPLY_ACTION_FORW (0x02), but (0x0A & 0x02) correctly detects
   * that the FORWARD bit is set.
   */
  /* Priority 1: Check DROP flag (highest priority) */
  if (action & PFCP_APPLY_ACTION_DROP) {
    bpf_debug("FAR action: DROP (seid=%llu)", seid);
    return RET_DROP;
  }

  /* Priority 2: Check FORWARD flag */
  if (action & PFCP_APPLY_ACTION_FORW) {
    bpf_debug("FAR action: FORWARD - decapsulating GTP-U (seid=%llu)", seid);
    int ret = gtpu_decap_ipv4(ctx, far);
    switch (ret) {
      case RET_SUCCESS: {
        bpf_debug("GTP-U decapsulation successful (seid=%llu)", seid);
        return RET_REDIRECT;
      }
      case RET_DROP: {
        bpf_debug("GTP-U decapsulation failed, dropping (seid=%llu)", seid);
        return RET_DROP;
      }
      case RET_FAILURE:
      default: {
        bpf_debug("GTP-U decapsulation error (seid=%llu, ret=%d)", seid, ret);
        return RET_FAILURE;
      }
    }
  }

  /* Priority 3: Check BUFFER flag */
  if (action & PFCP_APPLY_ACTION_BUFF) {
    bpf_debug("FAR action: BUFFER - not supported, dropping (seid=%llu)", seid);
    return RET_DROP;
  }

  /* Priority 4: Check NOTIFY_CP flag (informational, may be combined with
   * others) */
  if (action & PFCP_APPLY_ACTION_NOCP) {
    bpf_debug("FAR action: NOTIFY_CP - not supported (seid=%llu)", seid);
    /* Note: In full implementation, this would trigger notification to control
     * plane */
  }

  /* Priority 5: Check DUPLICATE flag */
  if (action & PFCP_APPLY_ACTION_DUPL) {
    bpf_debug("FAR action: DUPLICATE - not supported (seid=%llu)", seid);
    /* Note: In full implementation, this would duplicate the packet */
  }

  /* No valid action found or action not supported */
  bpf_debug(
      "No valid/supported FAR action (seid=%llu, action=0x%02x)", seid, action);
  return RET_FAILURE;
}

/* ========================================================================== */
/*                      FAR APPLICATION - DOWNLINK (N6)                       */
/* ========================================================================== */

/**
 * @brief Apply Forwarding Action Rule for downlink traffic
 *
 * Processes downlink packets based on FAR action flags per 3GPP TS 29.244 R16
 * Section 8.2.26. Apply Action is a bit field where multiple flags can be
 * set simultaneously. Therefore, we use bitwise checks (if statements with &)
 * rather than switch for action evaluation.
 *
 * Downlink flow (N6 → N3):
 * 1. Lookup FAR associated with PDR
 * 2. Check Apply Action flags:
 *    - DROP: Drop packet immediately
 *    - FORWARD to N3: Encapsulate in GTP-U
 *      • If QoS enabled: Pass to TC for traffic shaping
 *      • If QoS disabled: Direct redirect after encapsulation
 *    - FORWARD to N6: Forward without encapsulation (N6-LAN)
 *    - BUFFER: Not supported, drop packet
 * 3. Apply QoS gate status if QoS is enabled
 *
 * @param ctx XDP context
 * @param pdr_key PDR key (pdr_id, seid) for rule lookup
 * @param qfi QoS Flow Identifier for GTP-U encapsulation
 * @return RET_PASS (to TC), RET_REDIRECT (direct), RET_DROP, or RET_FAILURE
 *
 * @note Based on 3GPP TS 29.244 Release 16
 */
static __always_inline u32
apply_far_n6(struct xdp_md* ctx, struct pdrs_per_session pdr_key, u8 qfi) {
  struct rules_match_pdr* rules = {0};
  u64 seid                      = pdr_key.seid;

  rules = bpf_map_lookup_elem(&rules_match_pdr_map, &pdr_key);

  if (!rules) {
    bpf_debug("No rules found for PDR (seid=%llu)", seid);
    return RET_FAILURE;
  }

  /* Get FAR from rules */
  struct pfcp_far* far = &rules->far;
  if (!far || far->far_id.far_id == 0) {
    bpf_debug("Invalid FAR for session %llu", seid);
    return RET_FAILURE;
  }

  bpf_debug("Applying FAR ID=%u for session %llu", far->far_id.far_id, seid);

  /* Read action byte - may contain multiple flags set */
  u8 action = *((u8*) &far->apply_action);

  /*
   * Check each flag using bitwise AND (&) operator
   * We cannot use switch here because Apply Action is a bit field.
   * Example: if action=0x0A (FORW + NOCP), switch(0x0A) won't match
   * case APPLY_ACTION_FORW (0x02), but (0x0A & 0x02) correctly detects
   * that the FORWARD bit is set.
   */
  /* Priority 1: Check DROP flag (highest priority) */
  if (action & PFCP_APPLY_ACTION_DROP) {
    bpf_debug("FAR action: DROP (seid=%llu)", seid);
    return RET_DROP;
  }

  /* Priority 2: Check FORWARD flag */
  if (action & PFCP_APPLY_ACTION_FORW) {
    bpf_debug(
        "FAR action: FORWARD - encapsulating GTP-U (seid=%llu, qfi=%u)", seid,
        qfi);

    /* Encapsulate packet in GTP-U tunnel */
    int ret = gtpu_encap_ipv4(ctx, far, qfi);
    switch (ret) {
      case RET_SUCCESS: {
        bpf_debug("GTP-U encapsulation successful (seid=%llu)", seid);

        /* Check if QoS enforcement is enabled for this session */
        u32* qos_enabling =
            bpf_map_lookup_elem(&session_qos_enabled_map, &seid);
        if (!qos_enabling || *qos_enabling == 0) {
          /* QoS disabled - direct redirect to N3 interface */
          bpf_debug("QoS disabled for session %llu - direct redirect", seid);
          return RET_REDIRECT;
        }

        /* QoS enabled - check gate status */
        struct pfcp_qer* qer = &rules->qer;
        if (!qer) {
          bpf_debug("QER not found for session %llu", seid);
          return RET_FAILURE;
        }

        /* Check downlink gate status (3GPP TS 29.244 R16 Section 8.2.41) */
        if (qer->gate_status.dl_gate == 0) {
          /* Gate OPEN - pass to TC for QoS shaping */
          bpf_debug(
              "DL gate OPEN for session %llu, QFI %u - passing to TC", seid,
              qer->qos_flow_identifier.qfi);
          return RET_PASS;
        } else {
          /* Gate CLOSED - drop packet */
          bpf_debug(
              "DL gate CLOSED for session %llu, QFI %u - dropping", seid,
              qer->qos_flow_identifier.qfi);
          return RET_DROP;
        }
      }

      case RET_DROP: {
        bpf_debug("GTP-U encapsulation failed (seid=%llu) - dropping", seid);
        return RET_DROP;
      }

      case RET_FAILURE:
      default: {
        bpf_debug("GTP-U encapsulation error (seid=%llu, ret=%d)", seid, ret);
        return RET_FAILURE;
      }
    }
  }

  /* Priority 3: Check BUFFER flag */
  if (action & PFCP_APPLY_ACTION_BUFF) {
    bpf_debug(
        "FAR action: BUFFER - not supported in XDP, dropping (seid=%llu)",
        seid);
    return RET_DROP;
  }

  /* Priority 4: Check NOTIFY_CP flag (informational) */
  if (action & PFCP_APPLY_ACTION_NOCP) {
    bpf_debug("FAR action: NOTIFY_CP - not supported in XDP (seid=%llu)", seid);
    /* Note: In full implementation, this would trigger CP notification */
  }

  /* Priority 5: Check DUPLICATE flag */
  if (action & PFCP_APPLY_ACTION_DUPL) {
    bpf_debug("FAR action: DUPLICATE - not supported in XDP (seid=%llu)", seid);
    /* Note: In full implementation, this would duplicate the packet */
  }

  /* No valid action found or action not supported */
  bpf_debug(
      "No valid/supported FAR action (seid=%llu, action=0x%02x)", seid, action);
  return RET_FAILURE;
}

/* ==========================================================================
 */
/*                          XDP PROGRAM ENTRY POINTS */
/* ==========================================================================
 */

/**
 * @brief XDP program for uplink traffic (N3→N6)
 *
 * Handles GTP-U encapsulated packets from RAN:
 * 1. Parse GTP-U headers
 * 2. Lookup PFCP session by UE IP
 * 3. Match PDR with highest precedence
 * 4. Apply FAR (typically: decapsulate and forward)
 * 5. Redirect to N6 interface
 *
 * Entry point: Attached to N3 interface
 * Direction: RAN → Data Network
 *
 * @param ctx XDP context
 * @return XDP_REDIRECT, XDP_DROP, or XDP_PASS
 */
SEC("xdp")
int xdp_uplink(struct xdp_md* ctx) {
  bpf_debug("========< XDP Uplink: N3 --> N6 >========");

  /*
    |-----------------------------------------------------------------------|
    |----------------------------- N3 Entry Point --------------------------|
    |-----------------------------------------------------------------------|
    */
  void* data         = (void*) (long) ctx->data;
  void* data_end     = (void*) (long) ctx->data_end;
  struct ethhdr* eth = data;

  if ((void*) (eth + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return xdp_stats_record_action(ctx, XDP_DROP);
    // return XDP_DROP;
  }

  /*
    |-----------------------------------------------------------------------|
    |-------------------------- PFCP Session Lookup ------------------------|
    |----------------- (Find PFCP session with matching PDRs) --------------|
    |-----------------------------------------------------------------------|
    */
  u32 ue_ip    = 0;
  u8 qfi       = 0;
  u32 pkt_teid = 0;

  struct session_id* session =
      lookup_session_n3(data, data_end, eth, &ue_ip, &qfi, &pkt_teid);
  // session = lookup_session_n3(data, data_end, eth, &ue_ip, &qfi, &filter);

  if (!session) {
    bpf_debug(
        "PFCP Session Lookup (Find PFCP session with matching PDRs) failed. "
        "No "
        "session for UE IP: %pI4",
        ue_ip);
    return xdp_stats_record_action(ctx, XDP_PASS);
    // return XDP_PASS;
  }

  u64 seid                            = session->seid;
  u32 teid_ul                         = bpf_htonl(session->teid_ul);
  __attribute__((unused)) u32 teid_dl = bpf_htonl(session->teid_dl);
  bpf_debug(
      "Session found ( seid, teid_ul, teid_dl ) : ( %llu, %u, %u )", seid,
      teid_ul, teid_dl);

  /*
    |-----------------------------------------------------------------------|
    |------------------------ PFCP Session's Lookup ------------------------|
    |--- (Find matching PDR of the PFCP session with highest precedence) ---|
    |-----------------------------------------------------------------------|
    */
  struct pfcp_pdr* pdr_high_precedence =
      match_pdr_n3(seid, pkt_teid, ue_ip, qfi);
  // match_pdr_n3(seid, teid_ul, ue_ip, qfi);

  if (!pdr_high_precedence) {
    bpf_debug(
        "PFCP Session's Lookup (Find matching PDR of the PFCP session with "
        "highest precedence) failed");
    return xdp_stats_record_action(ctx, XDP_PASS);
    // return XDP_PASS;
  }

  u32 pdr_id = pdr_high_precedence->pdr_id.rule_id;
  bpf_debug("Highest precedence PDR found %x", pdr_id);

  /*
    |-----------------------------------------------------------------------|
    |--------------------- Apply Rules in Matching PDR ---------------------|
    |----------------------------- (FARs, QERs) ----------------------------|
    |-----------------------------------------------------------------------|
    */
  struct pdrs_per_session pdr_key = {0};
  pdr_key.pdr_id                  = pdr_id;
  pdr_key.seid                    = seid;

  u32 ret = apply_far_n3(ctx, pdr_key);
  switch (ret) {
    case RET_REDIRECT: {
      return xdp_stats_record_action(
          ctx, bpf_redirect_map(&redirect_interfaces_map, UPLINK, 0));
      // return bpf_redirect_map(&redirect_interfaces_map, UPLINK, 0);
      bpf_debug("Redirect: failed to redirect traffic to N6");
      break;
    }
    case RET_DROP: {
      bpf_debug("DROP: Packet should be dropped");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    case RET_FAILURE:
    default: {
      bpf_debug("PASS: something went wrong! pass packet to kernel");
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
/**
 * @brief XDP program for downlink traffic with QoS (N6→TC)
 *
 * Handles downlink packets requiring QoS shaping:
 * 1. Reserve metadata space for TC
 * 2. Lookup PFCP session by UE IP
 * 3. Match PDR with highest precedence
 * 4. Store QoS metadata (SEID, QFI) for TC
 * 5. Apply FAR (pass to TC or redirect)
 *
 * Entry point: Attached to N6 interface (when QoS enabled)
 * Direction: Data Network → TC → RAN
 *
 * @param ctx XDP context
 * @return XDP_PASS (for TC), XDP_REDIRECT, or XDP_DROP
 */

SEC("xdp")
int xdp_qos(struct xdp_md* ctx) {
  bpf_debug("========< XDP QoS: N6 --> TC >========");
  /*
   |-----------------------------------------------------------------------|
   |----------------------------- N6 Entry Point --------------------------|
   |-----------------------------------------------------------------------|
   */

  struct session_qfi* qos_metadata = {0};

  /* Reserve metadata for TC */
  if (bpf_xdp_adjust_meta(ctx, -(int) sizeof(struct session_qfi))) {
    bpf_debug("Failed to reserve metadata");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  void* data         = (void*) (long) ctx->data;
  void* data_end     = (void*) (long) ctx->data_end;
  struct ethhdr* eth = data;

  if ((void*) (eth + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /*
    |-----------------------------------------------------------------------|
    |-------------------------- PFCP Session Lookup ------------------------|
    |----------------- (Find PFCP session with matching PDRs) --------------|
    |-----------------------------------------------------------------------|
    */
  u32 ue_ip                       = 0;
  struct packet_filter pkt_filter = {0};

  struct session_id* session =
      lookup_session_n6(data, data_end, eth, &ue_ip, &pkt_filter);

  if (!session) {
    bpf_debug(
        "PFCP Session Lookup (Find PFCP session with matching PDRs) failed");
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  u64 seid                            = session->seid;
  u32 __attribute__((unused)) teid_ul = bpf_htonl(session->teid_ul);
  __attribute__((unused)) u32 teid_dl = bpf_htonl(session->teid_dl);
  bpf_debug(
      "Session found ( seid, teid_ul, teid_dl ) : ( %llu, %u, %u )", seid,
      teid_ul, teid_dl);

  /*
   |-----------------------------------------------------------------------|
   |------------------------ PFCP Session's Lookup ------------------------|
   |--- (Find matching PDR of the PFCP session with highest precedence) ---|
   |-----------------------------------------------------------------------|
   */
  u8 qfi = 0;
  struct pfcp_pdr* pdr_high_precedence =
      match_pdr_n6(seid, ue_ip, &qfi, &pkt_filter);

  if (!pdr_high_precedence) {
    bpf_debug(
        "PFCP Session's Lookup (Find matching PDR of the PFCP session with "
        "highest precedence) failed");
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  u32 pdr_id = pdr_high_precedence->pdr_id.rule_id;
  bpf_debug("Highest precedence PDR found %x", pdr_id);

  /*
    |-----------------------------------------------------------------------|
    |--------------------- Apply Rules in Matching PDR ---------------------|
    |----------------------------- (FARs, QERs) ----------------------------|
    |-----------------------------------------------------------------------|
    */
  /* Store QoS metadata for TC */
  qos_metadata = (struct session_qfi*) (long) ctx->data_meta;
  if ((void*) (qos_metadata + 1) > data) {
    bpf_debug("Error: Invalid Metadata");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  qos_metadata->seid = seid;
  qos_metadata->qfi  = qfi;
  bpf_debug("QoS metadata stored: SEID=%llu, QFI=%u", qos_metadata->seid, qfi);

  struct pdrs_per_session pdr_key = {0};
  pdr_key.pdr_id                  = pdr_id;
  pdr_key.seid                    = seid;

  u32 ret = apply_far_n6(ctx, pdr_key, qfi);

  switch (ret) {
    case RET_PASS: {
      bpf_debug("PASS: Pass the packet to TC layer");
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
    case RET_REDIRECT: {
      return xdp_stats_record_action(
          ctx, bpf_redirect_map(&redirect_interfaces_map, DOWNLINK, 0));
      bpf_debug("Redirect: failed to redirect traffic to N3");
      break;
    }
    case RET_DROP: {
      bpf_debug("DROP: Packet should be dropped");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    default: {
      bpf_debug("PASS: something went wrong! pass packet to kernel");
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/

/**
 * @brief XDP program for downlink traffic without QoS (N6→N3)
 *
 * Handles downlink packets without QoS requirements:
 * 1. Lookup PFCP session by UE IP
 * 2. Match PDR with highest precedence
 * 3. Apply FAR (typically: encapsulate and forward)
 * 4. Redirect to N3 interface
 *
 * Entry point: Attached to N6 interface (when QoS disabled)
 * Direction: Data Network → RAN
 *
 * @param ctx XDP context
 * @return XDP_REDIRECT, XDP_DROP, or XDP_PASS
 */
SEC("xdp")
int xdp_downlink(struct xdp_md* ctx) {
  bpf_debug("========< XDP Downlink: N6 --> N3 >========");

  /*
   |-----------------------------------------------------------------------|
   |----------------------------- N6 Entry Point --------------------------|
   |-----------------------------------------------------------------------|
   */
  void* data         = (void*) (long) ctx->data;
  void* data_end     = (void*) (long) ctx->data_end;
  struct ethhdr* eth = data;

  if ((void*) (eth + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /*
    |-----------------------------------------------------------------------|
    |-------------------------- PFCP Session Lookup ------------------------|
    |----------------- (Find PFCP session with matching PDRs) --------------|
    |-----------------------------------------------------------------------|
    */
  u32 ue_ip                       = 0;
  struct packet_filter pkt_filter = {0};
  struct session_id* session =
      lookup_session_n6(data, data_end, eth, &ue_ip, &pkt_filter);

  if (!session) {
    bpf_debug(
        "PFCP Session Lookup (Find PFCP session with matching PDRs) failed");
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  u64 seid                            = session->seid;
  __attribute__((unused)) u32 teid_ul = bpf_htonl(session->teid_ul);
  __attribute__((unused)) u32 teid_dl = bpf_htonl(session->teid_dl);
  bpf_debug(
      "Session found ( seid, teid_ul, teid_dl ) : ( %llu, %u, %u )", seid,
      teid_ul, teid_dl);

  /*
     |-----------------------------------------------------------------------|
     |------------------------ PFCP Session's Lookup ------------------------|
     |--- (Find matching PDR of the PFCP session with highest precedence) ---|
     |-----------------------------------------------------------------------|
     */
  u8 qfi = 0;
  struct pfcp_pdr* pdr_high_precedence =
      match_pdr_n6(seid, ue_ip, &qfi, &pkt_filter);

  if (!pdr_high_precedence) {
    bpf_debug(
        "PFCP Session's Lookup (Find matching PDR of the PFCP session with "
        "highest precedence) failed");
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  u32 pdr_id = pdr_high_precedence->pdr_id.rule_id;
  bpf_debug("Highest precedence PDR found 0x%x", pdr_id);

  /*
    |-----------------------------------------------------------------------|
    |--------------------- Apply Rules in Matching PDR ---------------------|
    |----------------------------- (FARs, QERs) ----------------------------|
    |-----------------------------------------------------------------------|
    */
  struct pdrs_per_session pdr_key = {0};
  pdr_key.pdr_id                  = pdr_id;
  pdr_key.seid                    = seid;

  u32 ret = apply_far_n6(ctx, pdr_key, qfi);

  switch (ret) {
    case RET_REDIRECT: {
      return xdp_stats_record_action(
          ctx, bpf_redirect_map(&redirect_interfaces_map, DOWNLINK, 0));
      bpf_debug("Redirect: failed to redirect traffic to N6");
      break;
    }
    case RET_DROP: {
      bpf_debug("DROP: Packet should be droped");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    default: {
      bpf_debug("PASS: something went wrong! pass packet to kernel");
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
  }
}

/* ========================================================================== */
/*                            LICENSE DECLARATION                             */
/* ========================================================================== */

char _license[] SEC("license") = "GPL";
