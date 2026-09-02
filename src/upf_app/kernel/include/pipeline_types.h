/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __PIPELINE_TYPES_H__
#define __PIPELINE_TYPES_H__

#include "custom_types.h"
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