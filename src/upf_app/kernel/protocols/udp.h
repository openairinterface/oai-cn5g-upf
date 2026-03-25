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
 * Changes:     Boy Scout cleanup — replaced commented-out stale declarations
 *              with a single concrete inline helper: parse_udp_gtpu().
 *              Centralises the repeated UDP bounds check + GTP-U port
 *              verification found across all N3 entry programs.
 */
// clang-format on

/**
 * @file  protocols/udp.h
 * @brief UDP header parsing helpers for XDP programs.
 *
 * Provides parse_udp_gtpu() which validates the outer UDP header and
 * confirms the GTP-U destination port (2152, IANA assigned).
 *
 * Used by:
 *     xdp_n3_entry.c,
 *     xdp_n3_eth_entry.c
 */

#ifndef PROTOCOLS_UDP_H
#define PROTOCOLS_UDP_H

#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include "linux/custom_types.h"
#include "protocols/gtpu.h" /* GTP_UDP_PORT */

/* ==========================================================================
 * parse_udp_gtpu — validate outer UDP and check GTP-U port
 * ========================================================================== */

/**
 * @brief Validate the outer UDP header and verify the GTP-U destination port.
 *
 * Called after the outer IPv4 header has been validated.  Non-GTP-U
 * UDP traffic (wrong destination port) sets @p pass so the caller can
 * hand the packet to the kernel stack.
 *
 * @param ip       Pointer to a previously validated outer IPv4 header.
 * @param data_end BPF bounds sentinel.
 * @param udp_out  Output: pointer to the outer UDP header.
 * @param pass     Output: true if the packet should be XDP_PASS'd
 *                 (non-GTP-U UDP traffic).
 * @return true if the header is valid and the port is GTP-U;
 *         false on bounds error (XDP_DROP) or wrong port (@p pass = true).
 */
static __always_inline bool parse_udp_gtpu(
    struct iphdr* ip, void* data_end, struct udphdr** udp_out, bool* pass) {
  *pass    = false;
  *udp_out = (void*) (ip + 1);

  if ((void*) (*udp_out + 1) > data_end) {
    bpf_debug("UDP: malformed outer UDP header");
    return false;
  }

  if (bpf_ntohs((*udp_out)->dest) != GTP_UDP_PORT) {
    bpf_debug(
        "UDP: dst port %u != GTP-U (%u) — passing to kernel",
        bpf_ntohs((*udp_out)->dest), GTP_UDP_PORT);
    *pass = true;
    return false;
  }

  return true;
}

#endif /* PROTOCOLS_UDP_H */