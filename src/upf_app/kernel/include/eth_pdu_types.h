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
 * Changes:     Boy Scout cleanup — split mac_pdu_session_key.h into
 *              eth_pdu_types.h (plain-C types, this file) and
 *              eth_pdu_maps.h (BPF map definitions).
 *              Renamed eth_session_id -> eth_session_id (removed double
 *              underscore convention).
 *              Replaced legacy <ie/teid.h> / <types.h> includes with
 *              concrete types (teid_t_ = u32).
 * 3GPP Refs:   3GPP TS 23.501 §5.6.10.3 — Ethernet PDU Session Type
 *              3GPP TS 29.281 V17.x.x §5.1 — GTP-U header
 */
// clang-format on

/**
 * @file  eth_pdu_types.h
 * @brief Ethernet PDU session type definitions.
 *
 * Defines the structs used for Ethernet PDU session MAC learning
 * and session context:
 *   - struct mac_pdu_session_value  DL tunnel info keyed by inner src MAC
 *   - struct eth_session_id         full session context keyed by UL TEID
 *
 * Contains only plain-C types — no BPF map definitions.
 * The BPF maps are in eth_pdu_maps.h.
 *
 * Used by: session_lookup_eth.c, xdp_n3_eth_entry.c, xdp_n6_eth_entry.c
 *
 * 3GPP Ref: 3GPP TS 23.501 §5.6.10.3 — Ethernet PDU Session Type
 */

#ifndef __ETH_PDU_TYPES_H__
#define __ETH_PDU_TYPES_H__

#include <linux/if_ether.h>
#include "linux/custom_types.h"

/* ==========================================================================
 * teid_t_ -- GTP-U Tunnel Endpoint Identifier type alias
 * ========================================================================== */

/**
 * @brief GTP-U Tunnel Endpoint Identifier (32-bit, network byte order).
 *
 * Plain u32 alias replacing the legacy struct fteid from ie/teid.h.
 * Used by the ETH PDU encapsulation path in xdp_n6_eth_entry.c.
 */
typedef u32 teid_t_;

/* ==========================================================================
 * struct arphdr_ipv4 -- IPv4 ARP header
 * ========================================================================== */

/**
 * @brief IPv4 ARP header for bounds-checked access in XDP programs.
 *
 * Used by xdp_n6_eth_entry.c to detect ARP packets addressed to the
 * UPF's own N6 IP and pass them to the kernel stack (XDP_PASS).
 *
 * Field names follow the Linux kernel arphdr convention (ar_*).
 * The struct is packed to avoid padding between variable-length fields.
 */
struct arphdr_ipv4 {
  __be16 ar_hrd;        /**< Hardware address format (ARPHRD_ETHER=1) */
  __be16 ar_pro;        /**< Protocol address format (ETH_P_IP=0x0800)*/
  unsigned char ar_hln; /**< Hardware address length (6 for Ethernet) */
  unsigned char ar_pln; /**< Protocol address length (4 for IPv4)     */
  __be16 ar_op;         /**< ARP opcode (REQUEST=1, REPLY=2)          */
  unsigned char ar_sha[ETH_ALEN]; /**< Sender hardware (MAC) address */
  __be32 ar_sip; /**< Sender IPv4 address                      */
  unsigned char ar_tha[ETH_ALEN]; /**< Target hardware (MAC) address */
  __be32 ar_tip; /**< Target IPv4 address                      */
} __attribute__((packed));

/* ==========================================================================
 * MAC learning table value
 * ========================================================================== */

/**
 * @brief Downlink GTP-U tunnel parameters keyed by inner source MAC.
 *
 * Stored in mac_pdu_session_map, keyed by inner Ethernet source MAC.
 * Written by session_lookup_eth.c on every uplink packet (BPF_ANY).
 * Read by xdp_n6_eth_entry.c to encapsulate downlink frames.
 */
struct mac_pdu_session_value {
  u32 teid;         /**< Downlink GTP-U TEID (network byte order) */
  u32 ipv4_address; /**< gNB IPv4 address (network byte order)    */
};

/* ==========================================================================
 * ETH session context
 * ========================================================================== */

/**
 * @brief Full ETH PDU session context keyed by uplink TEID.
 *
 * Stored in eth_session_mapping_map, keyed by uplink TEID.
 * Written by SessionProgramManager during PFCP Session Establishment.
 * Read by session_lookup_eth.c to resolve SEID and tunnel endpoints.
 *
 * Unlike IP PDU sessions (keyed by UE IP), ETH PDU sessions are keyed
 * by uplink TEID because the inner payload is a raw Ethernet frame with
 * no UE IP address to match against.
 */
struct eth_session_id {
  u32 teid_ul;      /**< Uplink F-TEID (RAN -> UPF)               */
  u32 teid_dl;      /**< Downlink F-TEID (UPF -> RAN)             */
  u32 ipv4_address; /**< gNB IPv4 address for DL encapsulation    */
  u64 seid;         /**< PFCP Session Endpoint Identifier         */
};

#endif /* __ETH_PDU_TYPES_H__ */