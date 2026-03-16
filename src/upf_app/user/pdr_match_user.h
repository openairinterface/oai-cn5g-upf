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
 * Changes:     V17.10.0 audit — fixed two §-refs in @see block:
 *                - Section 7.5.2.2 — Create PDR IE: in V17.10.0, §7.5.2.2
 *                  contains the PFCP Session Establishment Request overview;
 *                  the Create PDR grouped IE table is at §7.5.2.3.
 *                  Fixed: @see §7.5.2.3.
 *                - Section 8.2.5 — Create FAR IE: §8.2.5 = SDF Filter in
 *                  V17.10.0, not Create FAR.  Create FAR grouped IE is at
 *                  §7.5.2.4.  Fixed: @see §7.5.2.4.
 *              Boy Scout: added changelog with clang-format guards; updated
 *              @author / @date.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/**
 * @file pdr_match_user.h
 * @brief User-space manager for PDR matching BPF maps
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * PdrMatchProgram manages the BPF maps that back the XDP tail-call program
 * `pdr_match` (PROG_PDR_MATCH slot, index 1 in feature_dispatch_map).
 *
 * PDR matching is the second stage of the XDP pipeline.  After session
 * lookup resolves the SEID, pdr_match.c iterates PDRs in precedence order
 * and selects the best-matching PDR for the packet.  The result (FAR_ID,
 * QER_ID, URR_ID, BAR_ID, MAR_ID) is stored in the per-CPU packet context
 * and subsequent tail-call stages consume it.
 *
 * BPF Maps managed
 * ----------------
 *   pdrs_per_session_map — Ordered list of PDRs per session (key: SEID).
 *                          Value is a struct containing an array of pfcp_pdr_t
 *                          entries sorted by precedence (ascending).
 *                          Written by control plane; read by pdr_match.c.
 *
 *   rules_match_pdr_map  — Per-PDR rule associations (key: {SEID, PDR_ID}).
 *                          Maps each PDR to its FAR, QER, URR, BAR, MAR IDs.
 *                          Also carries the enabled rule flags bitmask so the
 *                          tail-call skip-chain can bypass disabled programs.
 *
 *   sdf_filters_map      — SDF (Service Data Flow) filter definitions
 *                          (key: {SEID, PDR_ID}).  Contains 5-tuple
 *                          classifiers for fine-grained flow matching
 *                          (src/dst IP, ports, protocol).
 *
 * Sorting guarantee
 * -----------------
 *   PDRs MUST be sorted by precedence before writing to pdrs_per_session_map.
 *   Callers (SessionProgramManager) invoke SortPdrs() before Setup/Update.
 *   The BPF program performs a linear scan and stops at the first match, so
 *   lower precedence values take priority (3GPP TS 29.244 Section 8.2.11).
 *
 * @see 3GPP TS 29.244 §7.5.2.3  — Create PDR grouped IE
 * @see 3GPP TS 29.244 §8.2.11   — Precedence
 * @see 3GPP TS 29.244 §7.5.2.4  — Create FAR grouped IE
 * @see kernel/xdp/pdr_match.c         — BPF tail-call program
 * @note Follows Google C++ Style Guide
 */

#ifndef PDR_MATCH_USER_H_
#define PDR_MATCH_USER_H_

#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <wrappers/BPFMap.hpp>
#include <pfcp_pdr.hpp>      // pfcp::pfcp_pdr (PFCP IE wrapper)
#include <pfcp_session.hpp>  // pfcp::pfcp_session
#include "rules_enabled_flags.h"

class BPFMap;

// ==========================================================================
// PDR rule association (stored in rules_match_pdr_map)
// ==========================================================================

/**
 * @struct pdr_rule_association
 * @brief Per-PDR rule IDs and enablement flags stored in rules_match_pdr_map
 *
 * The BPF pdr_match.c program writes this into the per-CPU packet context
 * after finding the best-matching PDR.  Subsequent tail-call stages read
 * the relevant rule ID for their processing.
 *
 * The rules_enabled field (RULE_QER/URR/BAR/MAR_ENABLED bitmask) drives the
 * tail-call skip-chain: a stage whose bit is clear is bypassed at zero cost.
 *
 * Must match the kernel definition in rules_matching_pdr.h.
 *
 * @see rules_enabled_flags.h for RULE_*_ENABLED bitmask definitions
 * @see 3GPP TS 29.244 Section 8.2.11 — Precedence
 */
struct pdr_rule_association {
  uint32_t pdr_id;         ///< PDR identifier
  uint32_t far_id;         ///< Associated FAR identifier (always present)
  uint32_t qer_id;         ///< Associated QER identifier (0 = none)
  uint32_t urr_id;         ///< Associated URR identifier (0 = none)
  uint32_t bar_id;         ///< Associated BAR identifier (0 = none)
  uint32_t mar_id;         ///< Associated MAR identifier (0 = none)
  uint32_t rules_enabled;  ///< RULE_*_ENABLED bitmask for skip-chain
  uint32_t _pad;
};

/**
 * @struct pdr_rule_key
 * @brief Compound key for rules_match_pdr_map and sdf_filters_map
 */
struct pdr_rule_key {
  uint64_t seid;    ///< PFCP Session Endpoint Identifier
  uint32_t pdr_id;  ///< PDR identifier
  uint32_t _pad;
} __attribute__((packed));

// ==========================================================================
// PdrMatchProgram
// ==========================================================================

/**
 * @class PdrMatchProgram
 * @brief User-space manager for PDR matching BPF maps
 *
 * Responsibilities:
 *   - Populate pdrs_per_session_map with precedence-sorted PDR arrays
 *   - Populate rules_match_pdr_map with FAR/QER/URR/BAR/MAR associations
 *   - Populate sdf_filters_map with 5-tuple SDF filter entries
 *   - Remove all entries on session deletion
 *   - Maintain the rules_enabled bitmask for tail-call skip-chain
 *
 * Thread Safety: Not thread-safe.  External locking required.
 *
 * @see pdr_match.c — corresponding BPF program
 * @note Follows Google C++ Style Guide
 */
class PdrMatchProgram {
 public:
  /**
   * @brief Constructor — receives shared BPFMap references
   *
   * @param session_pdrs_map   pdrs_per_session_map (PDR arrays per session)
   * @param rules_match_map    rules_match_pdr_map (PDR → rule IDs)
   * @param sdf_filter_map     sdf_filters_map (SDF 5-tuple filters)
   *
   * @throws std::invalid_argument if any map pointer is null
   */
  PdrMatchProgram(
      std::shared_ptr<BPFMap> session_pdrs_map,
      std::shared_ptr<BPFMap> rules_match_map,
      std::shared_ptr<BPFMap> sdf_filter_map);

  ~PdrMatchProgram() = default;

  // ==========================================================================
  // Session lifecycle
  // ==========================================================================

  /**
   * @brief Configure all PDR matching maps for a new or updated session
   *
   * Writes the sorted PDR array, all rule associations, and SDF filters.
   * PDRs MUST already be sorted by precedence by the caller.
   *
   * @param seid     PFCP session identifier
   * @param pdrs_ul  Uplink PDRs (sorted ascending by precedence)
   * @param pdrs_dl  Downlink PDRs (sorted ascending by precedence)
   * @param rules_enabled  Per-PDR rules_enabled bitmask (from ComputeFlags)
   */
  void PopulatePdrRulesMaps(
      uint64_t seid,
      const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_ul,
      const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_dl,
      uint32_t rules_enabled);

  /**
   * @brief Remove all PDR matching map entries for a session
   *
   * Removes entries from all three maps for every PDR in the session.
   *
   * @param seid  PFCP session identifier
   * @param pdrs  All PDRs (uplink + downlink combined)
   */
  void RemovePdrRulesMaps(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs);

  // ==========================================================================
  // Individual map population helpers
  // ==========================================================================

  /**
   * @brief Populate sdf_filters_map for a single PDR
   *
   * Extracts the SDF filter 5-tuple from the PDR's PDI and writes it.
   *
   * @param seid  PFCP session identifier
   * @param pdr   PDR containing the PDI with optional SDF filter IE
   */
  void PopulateSdfFilterMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_pdr>& pdr);

  /**
   * @brief Populate rules_match_pdr_map for a single PDR
   *
   * @param seid           PFCP session identifier
   * @param pdr            PDR to translate
   * @param rules_enabled  Rules bitmask for the tail-call skip-chain
   */
  void PopulateRulesMatchPdrMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_pdr>& pdr,
      uint32_t rules_enabled);

  // ==========================================================================
  // Map access
  // ==========================================================================

  /** @return Shared pointer to pdrs_per_session_map */
  std::shared_ptr<BPFMap> GetSessionPdrsMap() const {
    return session_pdrs_map_;
  }

  /** @return Shared pointer to rules_match_pdr_map */
  std::shared_ptr<BPFMap> GetRulesMatchMap() const { return rules_match_map_; }

  /** @return Shared pointer to sdf_filters_map */
  std::shared_ptr<BPFMap> GetSdfFilterMap() const { return sdf_filter_map_; }

 private:
  static pdr_rule_key MakePdrKey(uint64_t seid, uint32_t pdr_id);

  std::shared_ptr<BPFMap> session_pdrs_map_;  ///< PDR arrays per session
  std::shared_ptr<BPFMap> rules_match_map_;   ///< PDR → rule associations
  std::shared_ptr<BPFMap> sdf_filter_map_;    ///< SDF 5-tuple filter defs
};

#endif  // PDR_MATCH_USER_H_
