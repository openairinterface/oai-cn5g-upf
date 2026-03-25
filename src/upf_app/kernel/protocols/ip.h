/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */
// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Boy Scout cleanup — replaced stale forward declarations with
 *              three concrete inline helpers:
 *                parse_ipv4()      outer IPv4 validation
 *                parse_inner_ipv4() inner IPv4 (GTP-U payload) validation
 *                extract_5tuple()  SDF filter field extraction (TS 29.244 §8.2.5)
 *              Removed unreachable commented-out declarations.
 */
// clang-format on

/**
 * @file  protocols/ip.h
 * @brief IPv4 header parsing helpers for XDP programs.
 *
 * Provides inline helpers for:
 *   - Outer IPv4 validation (GTP-U tunnel outer header)
 *   - Inner IPv4 validation (UE payload after GTP-U decap)
 *   - 5-tuple extraction for SDF filter matching
 *
 * Used by:
 *    xdp_n3_entry.c  (outer + inner)
 *    xdp_n6_entry.c  (outer + 5-tuple)
 *    xdp_n3_eth_entry.c (outer only)
 */

#ifndef PROTOCOLS_IP_H
#define PROTOCOLS_IP_H

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include "linux/custom_types.h"

/* Byte offset of the IPv4 checksum field from the start of the packet
 * (after the Ethernet header). Used by checksum update helpers. */
#define IP_CSUM_OFFSET (sizeof(struct ethhdr) + offsetof(struct iphdr, check))

/* ==========================================================================
 * parse_ipv4 — validate and return the outer IPv4 header
 * ========================================================================== */

/**
 * @brief Validate the outer IPv4 header following an Ethernet header.
 *
 * @param eth      Pointer to a previously validated Ethernet header.
 * @param data_end BPF bounds sentinel.
 * @param ip_out   Output: pointer to the outer IPv4 header.
 * @return true if the header is valid; false on bounds error (XDP_DROP).
 */
static __always_inline bool parse_ipv4(
    struct ethhdr* eth, void* data_end, struct iphdr** ip_out) {
  *ip_out = (void*) (eth + 1);

  if ((void*) (*ip_out + 1) > data_end) {
    bpf_debug("IP: malformed outer IPv4 header");
    return false;
  }

  return true;
}

/* ==========================================================================
 * parse_inner_ipv4 — validate the inner IPv4 (UE payload)
 * ========================================================================== */

/**
 * @brief Validate the inner IPv4 header after GTP-U decapsulation.
 *
 * The inner source IP is the UE IP Address for uplink PDR matching
 * (TS 29.244 §8.2.62 — UE IP Address IE).
 *
 * @param inner    Pointer to the start of the inner IPv4 header
 *                 (one past the PDU Session Container).
 * @param data_end BPF bounds sentinel.
 * @param ip_out   Output: pointer to the inner IPv4 header.
 * @param ue_ip    Output: UE IPv4 source address (host byte order).
 * @return true if valid; false on bounds error (XDP_DROP).
 */
static __always_inline bool parse_inner_ipv4(
    void* inner, void* data_end, struct iphdr** ip_out, u32* ue_ip) {
  *ip_out = inner;

  if ((void*) (*ip_out + 1) > data_end) {
    bpf_debug("IP: malformed inner IPv4 header");
    return false;
  }

  *ue_ip = bpf_ntohl((*ip_out)->saddr);
  return true;
}

/* ==========================================================================
 * extract_5tuple — SDF filter field extraction (TS 29.244 §8.2.5)
 * ========================================================================== */

/**
 * @brief Extract the IP 5-tuple from a plain IPv4 packet.
 *
 * Populates the packet filter fields used for SDF matching
 * (TS 29.244 §8.2.5 — SDF Filter IE):
 *   src_ip, dst_ip, protocol, src_port, dst_port
 *
 * For non-TCP/UDP protocols, ports are set to 0 (wildcard match).
 *
 * @param ip       Pointer to a validated IPv4 header.
 * @param data_end BPF bounds sentinel.
 * @param src_ip   Output: source IPv4 address (host byte order).
 * @param dst_ip   Output: destination IPv4 address (host byte order).
 * @param proto    Output: IP protocol number.
 * @param src_port Output: source port (host byte order); 0 if not TCP/UDP.
 * @param dst_port Output: destination port (host byte order); 0 if not TCP/UDP.
 * @return true on success; false on bounds error (XDP_DROP).
 */
static __always_inline bool extract_5tuple(
    struct iphdr* ip, void* data_end, u32* src_ip, u32* dst_ip, u8* proto,
    u16* src_port, u16* dst_port) {
  *src_ip   = bpf_ntohl(ip->saddr);
  *dst_ip   = bpf_ntohl(ip->daddr);
  *proto    = ip->protocol;
  *src_port = 0;
  *dst_port = 0;

  switch (ip->protocol) {
    case IPPROTO_TCP: {
      struct tcphdr* tcp = (void*) (ip + 1);
      if ((void*) (tcp + 1) > data_end) {
        bpf_debug("IP: malformed TCP header in 5-tuple extraction");
        return false;
      }
      *src_port = bpf_ntohs(tcp->source);
      *dst_port = bpf_ntohs(tcp->dest);
      break;
    }
    case IPPROTO_UDP: {
      struct udphdr* udp = (void*) (ip + 1);
      if ((void*) (udp + 1) > data_end) {
        bpf_debug("IP: malformed UDP header in 5-tuple extraction");
        return false;
      }
      *src_port = bpf_ntohs(udp->source);
      *dst_port = bpf_ntohs(udp->dest);
      break;
    }
    default:
      /* Non-TCP/UDP: ports remain 0 — wildcard SDF match per TS 23.501 §5.7.1
       */
      break;
  }

  return true;
}

#endif /* PROTOCOLS_IP_H */