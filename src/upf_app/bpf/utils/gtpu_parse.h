/*
 * This file is a modified version from the source.
 * Copyright 2018 The Polycube Authors
 * Copyright 2021 Thiago Navarro
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __GTPU_PARSE_H__
#define __GTPU_PARSE_H__

// clang-format off
#include <types.h>
// clang-format on

#include <bpf_helpers.h>
#include <endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <protocols/gtpu.h>
#include <utils/logger.h>
#include <utils/utils.h>
#include <utils/csum.h>
#include <far_maps.h>
#include <pfcp_session_lookup_maps.h>
#include <mac_pdu_session_key.h>
#include <interfaces.h>
#include <stdbool.h>
#include <string.h>  //Needed for memcpy


/*****************************************************************************************************************/

static __always_inline bool retrieve_upf_iface_from_map(
    e_reference_point key, u32* iface_ip) {
  struct s_interface* map_element =
      bpf_map_lookup_elem(&m_upf_interfaces, &key);

  if (map_element) {
    *iface_ip = map_element->ipv4_address;
    return true;
  }

  return false;
}

/*****************************************************************************************************************/
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

/*****************************************************************************************************************/
static __always_inline u32
create_outer_header_gtpu_ipv4(struct xdp_md* ctx, struct mac_pdu_session_value* pdu_session) {
  // bpf_debug("Create Outer Header GTPU_IPv4");
  // bpf_debug("Original Packet: Data/UDP/IP/ETH");

  // Adjust space to the left.
  if (bpf_xdp_adjust_head(ctx, (int32_t) -ETH_GTP_ENCAPSULATED_SIZE)) {
    return XDP_DROP;
  }

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  bpf_debug("Total len %d", (int)(data_end - data));
  // Retrieve the N3 Interface IP address:
  e_reference_point n3_key = N3_INTERFACE;
  u32 n3_ip;
  if (!retrieve_upf_iface_from_map(n3_key, &n3_ip)) {
    bpf_debug("N3 interface is missing in UPF map, Drop the packet");
    return XDP_DROP;
  }

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

  struct ethhdr* ethh_orig = data + ETH_GTP_ENCAPSULATED_SIZE;

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

  struct iphdr* p_inner_ip = (void*) iph + ETH_GTP_ENCAPSULATED_SIZE;
  if ((void*) (p_inner_ip + 1) > data_end) {
    return XDP_DROP;
  }

  iph->version = 4;
  iph->ihl     = 5;  // No options
  iph->tos     = 0;
  iph->tot_len =
      bpf_htons(bpf_ntohs(p_inner_ip->tot_len) + ETH_GTP_ENCAPSULATED_SIZE);
  iph->id       = 0;       // No fragmentation
  iph->frag_off = 0x0040;  // Don't fragment; Fragment offset = 0
  iph->ttl      = 64;
  iph->protocol = IPPROTO_UDP;
  iph->check    = 0;
  iph->saddr    = n3_ip;
  iph->daddr = pdu_session->ipv4_address;

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
      bpf_ntohs(p_inner_ip->tot_len) + sizeof(struct ethhdr) + sizeof(*udph) + sizeof(struct gtpuhdr) +
      sizeof(struct gtpu_extn_pdu_session_container));
  udph->check = 0;

  /*
  |----------------------------------------------------------------|
  |-------------------------- Add GTP header ----------------------|
  |----------------------------------------------------------------|
  */
  // Update destination mac address
  if (!update_dst_mac_address(n3_ip, ethh)) {
    bpf_debug("N3's Next Hop MAC address not found! Drop the packet");
  }

  struct gtpuhdr* p_gtpuh = (void*) (udph + 1);
  if ((void*) (p_gtpuh + 1) > data_end) {
    return XDP_DROP;
  }

  u8 flags = GTP_EXT_FLAGS;
  __builtin_memcpy(p_gtpuh, &flags, sizeof(u8));
  p_gtpuh->message_type   = GTPU_G_PDU;
  p_gtpuh->message_length = bpf_htons(
      bpf_ntohs(p_inner_ip->tot_len) + sizeof(struct ethhdr) +
      sizeof(struct gtpu_extn_pdu_session_container) + 4);
  p_gtpuh->teid =
      bpf_htonl(pdu_session->teid);
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

#endif  // __CSUM_H__