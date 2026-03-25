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
 * Changes:     Boy Scout cleanup — added parse_eth() inline helper to
 *              centralise Ethernet header validation and EtherType dispatch.
 *              Removed stale eth_handle() forward declaration (unused).
 */
// clang-format on

/**
 * @file  protocols/eth.h
 * @brief Ethernet header parsing helpers for XDP programs.
 *
 * Provides a single inline helper used by all XDP entry points to
 * validate the Ethernet header and dispatch on EtherType.
 *
 * Used by:
 *   xdp_n3_entry.c,
 *   xdp_n6_entry.c,
 *   xdp_n3_eth_entry.c,
 *   xdp_n6_eth_entry.c
 */

#ifndef PROTOCOLS_ETH_H
#define PROTOCOLS_ETH_H

#include <linux/if_ether.h>
#include <linux/bpf.h>
#include "linux/custom_types.h"

/* ==========================================================================
 * eth_is_bcast_or_mcast -- classify inner destination MAC
 * ========================================================================== */

/**
 * @brief Return true if the MAC address is broadcast or multicast.
 *
 * Broadcast: FF:FF:FF:FF:FF:FF
 * Multicast: bit 0 of the first octet is set (IEEE 802.3 convention).
 *
 * Used by xdp_far_apply.c for Ethernet PDU session UL forwarding:
 * broadcast/multicast inner frames must be flooded to all ETH PDU
 * sessions via TC rather than unicast-forwarded (TS 23.501 §5.6.10.3).
 *
 * @param mac      6-byte Ethernet destination address.
 * @param data_end BPF bounds sentinel (unused — kept for symmetry with
 *                 other helpers so callers can pass ctx->data_end).
 * @return true if the address is broadcast or multicast.
 */
static __always_inline bool eth_is_bcast_or_mcast(
    const __u8* mac, const void* data_end) {
  /* Multicast bit: bit 0 of first octet (covers broadcast as a special case) */
  return (mac[0] & 0x01) != 0;
}

/* ==========================================================================
 * parse_eth — validate Ethernet header, return EtherType
 * ========================================================================== */

/**
 * @brief Validate the Ethernet header and return the L3 EtherType.
 *
 * Sets @p pass to true for frames that should be handed to the kernel
 * stack (ARP, IPv6, unknown).  Returns 0 on a hard bounds error
 * (caller should XDP_DROP).
 *
 * @param data     Start of XDP packet data.
 * @param data_end BPF bounds sentinel (one past end).
 * @param eth      Output: pointer to the validated Ethernet header.
 * @param pass     Output: true if the frame should be XDP_PASS'd.
 * @return ETH_P_IP when the frame carries an IPv4 payload that should
 *         be processed further; 0 on a hard bounds error; the raw
 *         EtherType for all other protocols (@p pass will be true).
 */
static __always_inline u16
parse_eth(void* data, void* data_end, struct ethhdr** eth, bool* pass) {
  *pass = false;
  *eth  = data;

  if ((void*) (*eth + 1) > data_end) {
    bpf_debug("ETH: malformed Ethernet header");
    return 0;
  }

  u16 proto = bpf_ntohs((*eth)->h_proto);

  switch (proto) {
    case ETH_P_IP:
      return ETH_P_IP;

    case ETH_P_ARP:
      bpf_debug("ETH: ARP — passing to kernel");
      *pass = true;
      return ETH_P_ARP;

    case ETH_P_IPV6:
      bpf_debug("ETH: IPv6 not supported — passing to kernel");
      *pass = true;
      return ETH_P_IPV6;

    default:
      bpf_debug("ETH: unknown EtherType 0x%04x — passing to kernel", proto);
      *pass = true;
      return proto;
  }
}

#endif /* PROTOCOLS_ETH_H */
