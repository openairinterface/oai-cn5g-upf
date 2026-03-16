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
 * Changes:     V17.10.0 integration — propagate PDR mar_id to pctx:
 *                - pfcp_pdr.h now carries mar_id (__u16, §8.2.123).  After a
 *                  PDR is selected, its mar_id is written to
 *                  pctx->pdr_mar_id so that mar_apply.c can follow the
 *                  PDR→MAR chain without a second map lookup.
 *              Boy Scout cleanup:
 *                - Replaced bare @file block with changelog + clang-format
 *                  guards per project coding rules.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §8.2.21   PDR ID            §8.2.36   UE IP Address
 *              §8.2.123  MAR ID (new in V17.10.0)
 */
// clang-format on

/**
 * @file pdr_match.c
 * @brief PDR (Packet Detection Rule) matching for IP PDU sessions
 *
 * Shared program for both uplink and downlink. Branches on
 * pctx->session_type to select the correct matching logic:
 *
 *   - IP_UPLINK:   Source Interface = ACCESS (N3), F-TEID, QFI
 *                  (first-match per TS 29.244 §8.2.21)
 *   - IP_DOWNLINK: Source Interface = CORE (N6), UE IP, SDF filter
 *                  (best-match: specificity > precedence)
 *
 * PDR matching is the core of the 5G UPF packet classification engine.
 * Each PDR contains a PDI (Packet Detection Information, TS 29.244 §8.2.24)
 * that defines the matching criteria.
 *
 * Chain: Entry → Session Lookup → [PDR_MATCH] → FAR → [QER] → [URR] → [MAR]
 *
 * @see 3GPP TS 29.244 §8.2.21 - PDR ID IE
 * @see 3GPP TS 29.244 §8.2.24 - PDI (Packet Detection Information)
 * @see 3GPP TS 29.244 §8.2.25 - Precedence IE
 * @see 3GPP TS 29.244 §8.2.5 - SDF Filter IE
 */

#define KBUILD_MODNAME pdr_match

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "linux/custom_types.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"
#include "utils/types.h"

/* PFCP structures */
#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_pdr.h"
#include "ie/group_ie/pdi.h"

/* Maps and definitions */
#include "upf_xdp_maps.h"
#include "interfaces.h"
#include "sdf_filter.h"
#include "eth_pdu_maps.h"
#include "tail_call_dispatch.h"
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

/* ========================================================================== */
/*                     SDF FILTER MATCHING (TS 29.244 §8.2.5)                 */
/* ========================================================================== */

/**
 * @brief Match packet 5-tuple against SDF Filter IE
 *
 * SDF (Service Data Flow) filters define the traffic pattern for a QoS
 * flow. A match means this packet belongs to the QoS flow identified
 * by the associated QFI.
 *
 * Matching fields (TS 29.244 §8.2.5):
 * - Flow Description: IP protocol, src/dst IP with mask, src/dst port range
 *
 * @param pctx Packet context with 5-tuple
 * @param sdf SDF filter to match against
 * @return 1 if matched, 0 if not
 */
static __always_inline u32 match_sdf_filter(
    const struct packet_context* pctx, const struct sdf_filtr* sdf) {
  u8 pkt_proto     = pctx->pkt_filter_protocol;
  u16 pkt_src_port = pctx->pkt_filter_src_port;
  u16 pkt_dst_port = pctx->pkt_filter_dst_port;
  u32 pkt_src_ip   = bpf_htonl(pctx->pkt_filter_src_ip);
  u32 pkt_dst_ip   = bpf_htonl(pctx->pkt_filter_dst_ip);

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
    bpf_debug("SDF Filter matched");
    return 1;
  }

  bpf_debug("SDF Filter not matched");
  return 0;
}

/* ========================================================================== */
/*               SDF SPECIFICITY SCORING (PDR selection)                      */
/* ========================================================================== */

/**
 * @brief Calculate SDF filter specificity score for PDR selection
 *
 * When multiple PDRs match a packet, this score helps select the most
 * specific rule. Higher scores indicate more specific matches. This
 * prevents generic "any protocol" rules (protocol=0) from shadowing
 * specific protocol rules (protocol=1 for ICMP, protocol=6 for TCP, etc.).
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
 * @param pkt_proto Packet's IP protocol number
 * @return Specificity score (higher = more specific)
 */
static __always_inline u32
calc_sdf_specificity(const struct sdf_filtr* sdf, u8 pkt_proto) {
  u32 score = 0;

  /* Protocol specificity (most important factor) */
  if (sdf->protocol == 0) {
    /* Protocol = 0 means "any IP protocol" - least specific */
    score += 100; /* Wildcard: "any IP protocol" */
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

  /* Port range specificity — reward narrow ranges */
  u16 src_port_range = sdf->src_port.upper_bound - sdf->src_port.lower_bound;
  u16 dst_port_range = sdf->dst_port.upper_bound - sdf->dst_port.lower_bound;

  /* Scale down to prevent overwhelming protocol score */
  if (src_port_range < 65535) {
    score += (65535 - src_port_range) / 1000; /* 0-65 pts */
  }

  if (dst_port_range < 65535) {
    score += (65535 - dst_port_range) / 1000; /* 0-65 pts */
  }

  return score;
}

/* ========================================================================== */
/*                      PDR MATCHING — UPLINK (N3→N6)                         */
/* ========================================================================== */

/**
 * @brief Find matching PDR with highest precedence for uplink
 *
 * Iterates through all PDRs for the session and finds the one that:
 * 1. Has N3 (ACCESS) as Source Interface (TS 29.244 §8.2.2)
 * 2. Matches F-TEID if present (TS 29.244 §8.2.3)
 * 3. Matches QFI if present (TS 29.244 §8.2.89)
 * 4. Matches UE IP Address if present (optional for UL, TS 29.244 §8.2.36)
 *
 * Returns first match (uplink uses first-match, not best-match).
 *
 * @param seid PFCP Session Endpoint Identifier
 * @param pkt_teid TEID from incoming GTP-U header
 * @param pkt_ue_ip UE IP address (inner source)
 * @param pkt_qfi QFI from PDU Session Container
 * @return Pointer to matched PDR or NULL
 */
static __always_inline struct pfcp_pdr* match_pdr_n3(
    u64 seid, u32 pkt_teid, u32 pkt_ue_ip, u8 pkt_qfi) {
  struct pfcp_pdr(*pdrs)[MAX_PDRS_PER_PDU_SESSION] =
      bpf_map_lookup_elem(&pdrs_per_session_map, &seid);

  if (!pdrs) {
    bpf_debug("PDR Lookup: No PDRs for SEID = %llu", seid);
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

    /* Skip invalid/empty PDR entries */
    if (pdr->pdr_id.rule_id == 0) continue;

    /* Retrieve PDI from PDR */
    struct pdi pdi = pdr->pdi;

    /* Retrieve UE IP from PDI */
    u32 ipaddr = bpf_htonl(pdi.ue_ip_address.ipv4_address.s_addr);

    /*
     * Check UE IP match ONLY if present in PDR.
     * Per 3GPP TS 29.244: UE IP is OPTIONAL in PDI for uplink PDRs (TS 29.244
     * §8.2.36). Open5GS doesn't include UE IP in uplink PDRs - this is
     * compliant.
     */
    if ((ipaddr != 0) && (ipaddr != pkt_ue_ip)) continue;

    /* Source Interface must be ACCESS (N3) (§8.2.2) */
    if (bpf_htonl(pdi.source_interface.interface_value) !=
        INTERFACE_VALUE_ACCESS)
      continue;

    /* F-TEID match if present (§8.2.3) */
    if ((pdi.fteid.teid != 0) && (pdi.fteid.teid != pkt_teid)) continue;

    /* QFI match if present (§8.2.89) */
    if ((pdi.qfi.qfi != 0) && (pdi.qfi.qfi != pkt_qfi)) continue;

    bpf_debug("PDR matched : Rule ID = %u", pdr->pdr_id.rule_id);
    bpf_debug(
        "  PDI: ( pkt_ue_ip, pdi_ue_ip ) = ( %pI4, %pI4 )", &pkt_ue_ip,
        &ipaddr);
    bpf_debug(
        "  PDI: ( pkt_teid, pdi_fteid ) = ( %d, %d )", pkt_teid,
        pdi.fteid.teid);
    bpf_debug("  PDI: ( pkt_qfi, pdi_qfi ) = ( %u, %u )", pkt_qfi, pdi.qfi.qfi);
    return pdr;
  }

  // No match found
  return NULL;
}

/* ========================================================================== */
/*                      PDR MATCHING — DOWNLINK (N6→N3)                       */
/* ========================================================================== */

/**
 * @brief Find best matching PDR for downlink traffic
 *
 * Uses specificity scoring + precedence for best-match selection
 * per TS 29.244 §8.2.25 (Precedence IE):
 *   1. Source Interface must be CORE (N6) (§8.2.2)
 *   2. UE IP Address must match (§8.2.36)
 *   3. SDF filter match if QER enabled (§8.2.5)
 *   4. Highest specificity wins, then lowest precedence value
 *
 * When QER is disabled (no QoS enforcement), returns the first
 * matching downlink PDR without SDF evaluation.
 *
 * @param seid PFCP Session Endpoint Identifier
 * @param pkt_ue_ip UE IP address (destination for downlink)
 * @param qfi_out Output: QFI from matched PDR
 * @param pctx Packet context with 5-tuple for SDF matching
 * @return Pointer to best matching PDR or NULL
 */
static __always_inline struct pfcp_pdr* match_pdr_n6(
    u64 seid, u32 pkt_ue_ip, u8* qfi_out, struct packet_context* pctx) {
  struct pfcp_pdr(*pdrs)[MAX_PDRS_PER_PDU_SESSION] =
      bpf_map_lookup_elem(&pdrs_per_session_map, &seid);

  if (!pdrs) {
    bpf_debug("PDR Lookup: No PDRs for SEID = %llu", seid);
    return NULL;
  }

  /* Variables for tracking best match */
  struct pfcp_pdr* best_pdr = NULL;
  u32 best_specificity      = 0;
  u32 best_precedence       = 0xFFFFFFFF;
  u8 best_qfi               = 0;

  /*
   * Check QER enable flag from pctx->rules_enabled.
   * If QER is not enabled, skip SDF matching - return first DL PDR.
   */
  bool qos_enabled = (pctx->rules_enabled & RULE_QER_ENABLED) != 0;

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

    if (pdr->pdr_id.rule_id == 0) continue;

    /* Retrieve PDI from PDR */
    struct pdi pdi = pdr->pdi;

    /* Retrieve UE IP from PDI */
    u32 ipaddr = bpf_htonl(pdi.ue_ip_address.ipv4_address.s_addr);

    /* UE IP Address must match for DL */
    if (ipaddr != pkt_ue_ip) continue;
    /* Check UE IP */
    /* TODO:
     * Check if this is correct
     * in case of framed_routing
     */

    /* Source Interface must be CORE (N6) */
    u32 source_interface = pdi.source_interface.interface_value;

    if (source_interface != INTERFACE_VALUE_CORE) continue;

    u8 pdr_qfi     = pdi.qfi.qfi;
    u32 precedence = pdr->precedence.precedence;

    /* QoS disabled: return first matching DL PDR */
    if (!qos_enabled) {
      bpf_debug(
          "QER not enabled for SEID = %llu - "
          "first-match PDR",
          seid);
      *qfi_out = pdr_qfi;
      return pdr;
    }

    /* QoS enabled: evaluate SDF filter (§8.2.5) */
    struct session_qfi sdf_key = {0};

    sdf_key.seid = seid;
    sdf_key.qfi  = pdr_qfi;

    const struct sdf_filtr* sdf =
        bpf_map_lookup_elem(&sdf_filters_map, &sdf_key);

    if (!sdf) {
      /*
       * No SDF filter for this QFI - default/non-GBR
       * traffic. Only select if no better match found.
       */
      bpf_debug(
          "SDF not found for QFI = %u - "
          "treating as non-GBR flow",
          pdr_qfi);
      if (!best_pdr) {
        best_pdr        = pdr;
        best_precedence = precedence;
        best_qfi        = pdr_qfi;
        bpf_debug(
            "First match (no SDF): PDR %u (precedence = %u, QFI = %u)",
            pdr->pdr_id.rule_id, precedence, pdr_qfi);
      }
      continue;
    }

    /* Log SDF lookup */
    bpf_debug("SDF key ( seid, qfi ): ( %llu, %u )", sdf_key.seid, sdf_key.qfi);

    /* Check SDF filter match */
    if (!match_sdf_filter(pctx, sdf)) {
      bpf_debug("SDF not matched for PDR %u", pdr->pdr_id.rule_id);
      continue;
    }

    /* SDF matched - calculate specificity */
    u32 specificity = calc_sdf_specificity(sdf, pctx->pkt_filter_protocol);

    bpf_debug("PDR %u Matched: ", pdr->pdr_id.rule_id);
    bpf_debug("   - Specificity = %u", specificity);
    bpf_debug("   - Precedence  = %u", precedence);
    bpf_debug("   - QFI         = %u", pdr_qfi);

    /* Determine if this is a better match (§8.2.25) */
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
/*                  PDR MATCHING -- ETH PDU UPLINK (N3->N6)                  */
/* ========================================================================== */

/**
 * @brief Find matching PDR for ETH PDU uplink traffic
 *
 * ETH PDU sessions (TS 23.501 §5.6.10.3) have no UE IP address.
 * PDR matching uses only:
 *   1. Source Interface = ACCESS (N3) (§8.2.2)
 *   2. F-TEID match if present (§8.2.3)
 *   3. QFI match if present (§8.2.89)
 *
 * No SDF filter evaluation -- Ethernet frames don't carry IP 5-tuples
 * at the PDU session level. Uses eth_session_pdrs_map (separate from
 * IP PDU session PDRs).
 *
 * @param seid     PFCP Session Endpoint Identifier
 * @param pkt_teid TEID from incoming GTP-U header
 * @param pkt_qfi  QFI from PDU Session Container
 * @return Pointer to matched PDR or NULL
 */
static __always_inline struct pfcp_pdr* match_pdr_eth_n3(
    u64 seid, u32 pkt_teid, u8 pkt_qfi) {
  struct pfcp_pdr(*pdrs)[MAX_PDRS_PER_PDU_SESSION] =
      bpf_map_lookup_elem(&eth_session_pdrs_map, &seid);

  if (!pdrs) {
    bpf_debug("ETH PDR Lookup: No PDRs for SEID = %llu", seid);
    return NULL;
  }

#pragma clang loop unroll(full)
  for (int i = 0; i < MAX_PDRS_PER_PDU_SESSION_LIMIT; i++) {
    if (i >= MAX_PDRS_PER_PDU_SESSION) break;
    struct pfcp_pdr* pdr = &(*pdrs)[i];

    if (pdr->pdr_id.rule_id == 0) continue;

    struct pdi pdi = pdr->pdi;

    /* Source Interface must be ACCESS (N3) (§8.2.2) */
    if (bpf_htonl(pdi.source_interface.interface_value) !=
        INTERFACE_VALUE_ACCESS)
      continue;

    /* F-TEID match if present (§8.2.3) */
    if ((pdi.fteid.teid != 0) && (pdi.fteid.teid != pkt_teid)) continue;

    /* QFI match if present (§8.2.89) */
    if ((pdi.qfi.qfi != 0) && (pdi.qfi.qfi != pkt_qfi)) continue;

    bpf_debug("ETH PDR matched (§8.2.21): Rule ID=%u", pdr->pdr_id.rule_id);
    bpf_debug(
        "  PDI: ( pkt_teid, pdi_fteid ) = ( %d, %d )", pkt_teid,
        pdi.fteid.teid);
    bpf_debug("  PDI: ( pkt_qfi, pdi_qfi ) = ( %u, %u )", pkt_qfi, pdi.qfi.qfi);
    return pdr;
  }

  return NULL;
}

/* ========================================================================== */
/*                        PDR MATCH ENTRY POINT                               */
/* ========================================================================== */

SEC("xdp")
int pdr_match(struct xdp_md* ctx) {
  bpf_debug("=== PDR Match ===");

  /*
  |-----------------------------------------------------------------------|
  |------------------------ PFCP Session's Lookup ------------------------|
  |--- (Find matching PDR of the PFCP session with highest precedence) ---|
  |-----------------------------------------------------------------------|
 */

  bpf_debug(
      "|-----------------------------------------------------------------------"
      "|");
  bpf_debug(
      "|------------------------ PFCP Session's Lookup "
      "------------------------|");
  bpf_debug(
      "|--- (Find matching PDR of the PFCP session with highest precedence) "
      "---|");
  bpf_debug(
      "|-----------------------------------------------------------------------"
      "|");

  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("Error: Failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  u64 seid  = pctx->seid;
  u32 ue_ip = pctx->ue_ip;

  struct pfcp_pdr* pdr = NULL;
  u8 qfi               = pctx->qfi;

  if (IS_ETH_PDU(pctx->session_type)) {
    /*
     * ETH PDU UL: match by TEID + QFI only (no UE IP, no SDF).
     * ETH PDU DL is self-contained in upf_n6_eth_entry.c and
     * never reaches PDR match.
     */
    pdr = match_pdr_eth_n3(seid, pctx->pkt_teid, qfi);
  } else if (IS_UPLINK(pctx->session_type)) {
    /* IP PDU UL: match by F-TEID, QFI, Source Interface=ACCESS */
    pdr = match_pdr_n3(seid, pctx->pkt_teid, ue_ip, qfi);
  } else {
    /* IP PDU DL: match by UE IP, SDF, Source Interface=CORE */
    pdr = match_pdr_n6(seid, ue_ip, &qfi, pctx);
  }

  if (!pdr) {
    bpf_debug("PDR match failed for SEID=%llu (§8.2.21)", seid);
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  u32 pdr_id = pdr->pdr_id.rule_id;

  bpf_debug("PDR selected: Rule ID=0x%x (§8.2.21)", pdr_id);

  pctx->pdr_id = pdr_id;
  pctx->qfi    = qfi; /* Updated by match_pdr_n6 for downlink */

  /*
   * Propagate PDR's MAR ID (§8.2.123) — V17.10.0 addition.
   *
   * pfcp_pdr.h now carries a mar_id field (__u16) that identifies which
   * MAR rule applies to packets matched by this PDR.  mar_apply.c reads
   * pctx->pdr_mar_id to select the correct ATSSS steering configuration.
   * If 0, the session has no ATSSS MAR and mar_apply.c will fall through
   * to the default (3GPP) path.
   */
  pctx->pdr_mar_id = pdr->mar_id; /* 0 if no MAR associated */

  bpf_debug(
      "PDR selected: Rule ID=0x%x, MAR ID=%u (§8.2.21/§8.2.123)", pdr_id,
      pctx->pdr_mar_id);

  bpf_debug("Error: Tail call to PROG_FAR_APPLY failed");
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
