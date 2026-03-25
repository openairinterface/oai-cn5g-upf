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
 * Changes:     Boy Scout cleanup — consolidated session_id.h and
 *              rules_matching_pdr.h into this single file since both
 *              serve the pipeline dispatch purpose.
 *              No functional changes to struct content.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §8.2.21 — PDR ID IE
 *              3GPP TS 29.244 V17.10.0 §7.5.2   — Session Establishment
 */
// clang-format on

/**
 * @file  pipeline_types.h
 * @brief Core pipeline data types: session identity and PDR rule association.
 *
 * Consolidates session_id.h and rules_matching_pdr.h into one file:
 *
 *   - struct session_id       session lookup result (SEID + TEIDs)
 *   - struct pdrs_per_session map key: {pdr_id, seid}
 *   - struct rules_match_pdr  full rule set for a matched PDR
 *
 * Contains only plain-C types — no BPF map definitions.
 * The BPF maps are in pipeline_maps.h.
 *
 * Used by: session_lookup_ip.c, pdr_match.c, xdp_far_apply.c,
 *          xdp_qer_apply.c, xdp_urr_apply.c, xdp_bar_apply.c,
 *          xdp_mar_apply.c, session_lookup_eth.c
 *
 * 3GPP Ref: 3GPP TS 29.244 V17.10.0 §7.5.2 — PFCP Session Establishment
 *           3GPP TS 29.244 V17.10.0 §8.2.21 — PDR ID IE
 */

#ifndef __PIPELINE_TYPES_H__
#define __PIPELINE_TYPES_H__

#include "linux/custom_types.h"
#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_qer.h"
#include "pfcp/pfcp_urr.h"
#include "pfcp/pfcp_bar.h"
#include "pfcp/pfcp_mar.h"

/* ==========================================================================
 * Session identity
 * ========================================================================== */

/**
 * @brief Session lookup result from session_by_ue_ip_map.
 *
 * Returned by session_lookup_ip.c after resolving the UE IP -> SEID mapping.
 * Stored in packet_context for use by downstream pipeline stages.
 *
 * 3GPP TS 29.244 §7.2.2.1 — SEID assignment
 * 3GPP TS 29.244 §8.2.3   — F-TEID IE
 */
struct session_id {
  u32 teid_ul; /**< Uplink F-TEID (RAN -> UPF tunnel endpoint)   */
  u32 teid_dl; /**< Downlink F-TEID (UPF -> RAN tunnel endpoint) */
  u64 seid;    /**< PFCP Session Endpoint Identifier             */
};

/* ==========================================================================
 * PDR map key
 * ========================================================================== */

/**
 * @brief Composite key for rules_match_pdr_map.
 *
 * PDR IDs are unique within a session but not globally — the SEID is
 * required to disambiguate across sessions.
 *
 * 3GPP TS 29.244 §8.2.21 — PDR ID IE
 */
struct pdrs_per_session {
  u16 pdr_id; /**< Packet Detection Rule ID (session-scoped)   */
  u64 seid;   /**< PFCP Session Endpoint Identifier            */
};

/* ==========================================================================
 * Per-PDR rule set
 * ========================================================================== */

/**
 * @brief Complete set of rules associated with a matched PDR.
 *
 * Populated by control plane (SessionProgramManager) during PFCP Session
 * Establishment (§7.5.2) or Modification (§7.5.4).
 * Read sequentially by each tail-call program in the pipeline:
 *
 *   pdr_match -> far_apply (far)
 *             -> qer_apply (qer)  [if RULE_QER_ENABLED]
 *             -> urr_apply (urr)  [if RULE_URR_ENABLED]
 *             -> bar_apply (bar)  [if RULE_BAR_ENABLED]
 *             -> mar_apply (mar)  [if RULE_MAR_ENABLED]
 *
 * URR/BAR runtime counters are stored separately in their own maps
 * (urr_volume_counters_map, bar_state_map) to avoid being overwritten
 * by control-plane session modifications.
 *
 * 3GPP TS 29.244 §8.2 — Information Elements
 */
struct rules_match_pdr {
  struct pfcp_far far; /**< Forwarding Action Rule  (§8.2.22-26) mandatory */
  struct pfcp_qer qer; /**< QoS Enforcement Rule    (§8.2.40-43) optional  */
  struct pfcp_urr urr; /**< Usage Reporting Rule    (§8.2.44-48) optional  */
  struct pfcp_bar bar; /**< Buffering Action Rule   (§8.2.57)    optional  */
  struct pfcp_mar mar; /**< Multi-Access Rule       (§8.2.123)   optional  */
};

#endif /* __PIPELINE_TYPES_H__ */