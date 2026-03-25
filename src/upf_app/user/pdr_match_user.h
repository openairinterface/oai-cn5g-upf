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
 *              Added skeleton ownership following the QERProgram pattern:
 *                - PdrMatchProgram now owns xdp_pdr_match_c skeleton +
 *                  ProgramLifeCycle<xdp_pdr_match_c>.
 *                - Constructor opens skeleton (no map args needed at
 *                  construction time).
 *                - SetMaps() replaces old constructor map injection so
 *                  UPF_XDPProgram can share map FDs after load.
 *                - GetBpfObject() for map sharing.
 *                - GetXdpProgram() for tail_call_progs_map insertion.
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
 * PdrMatchProgram owns the xdp_pdr_match_c BPF skeleton and manages the
 * BPF maps that back the XDP tail-call program `pdr_match`
 * (PROG_PDR_MATCH slot, index 2 in tail_call_progs_map).
 *
 * Skeleton Lifecycle (driven by UPF_XDPProgram)
 * --------------------------------------------------
 *   1. PdrMatchProgram() -- opens xdp_pdr_match_c skeleton.
 *   2. UPF_XDPProgram::ShareMapsFromPrimary() -- reuses primary map FDs.
 *   3. Load()     -- loads skeleton (map FDs already shared).
 *   4. SetMaps()  -- receives BPFMap wrappers from UPF_XDPProgram.
 *   5. GetXdpProgram() -- provides FD for tail_call_progs_map slot.
 *   6. Destructor -- destroys skeleton via ProgramLifeCycle.
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

#include <ProgramLifeCycle.hpp>
#include <xdp_pdr_match_skel.h>
#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <wrappers/BPFMap.hpp>
#include <pfcp_pdr.hpp>     /* pfcp::pfcp_pdr (PFCP IE wrapper)  */
#include <pfcp_session.hpp> /* pfcp::pfcp_session                */
#include "BPFProgram.h"
#include "rules_enabled_flags.h"

class BPFMap;
class BPFMaps;

/* ==========================================================================
 * Type alias
 * ========================================================================== */

using PdrMatchProgramLifeCycle = ProgramLifeCycle<xdp_pdr_match_kern_c>;

/* ==========================================================================
 * PDR rule association (stored in rules_match_pdr_map)
 * ========================================================================== */

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

/* ==========================================================================
 * PdrMatchProgram
 * ========================================================================== */

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
class PdrMatchProgram : public BPFProgram {
 public:
  // ==========================================================================
  // Constructor / Destructor
  // ==========================================================================

  /**
   * @brief Constructor -- opens xdp_pdr_match skeleton.
   * Does NOT inject maps; call SetMaps() after UPF_XDPProgram
   * has called ShareMapsFromPrimary() and InitializeMaps().
   * @throws std::runtime_error if skeleton open fails.
   */
  PdrMatchProgram();
  virtual ~PdrMatchProgram() = default;

  // ==========================================================================
  // Skeleton lifecycle
  // ==========================================================================

  /** @brief Load skeleton (call after map sharing is complete). */
  void Load();

  /** @brief Return the underlying BPF object (for map sharing). */
  struct bpf_object* GetBpfObject() const;

  /** @brief Return XDP program pointer for tail_call_progs_map insertion. */
  struct bpf_program* GetXdpProgram() const;

  // ==========================================================================
  // Map injection
  // ==========================================================================

  /**
   * @brief Receive BPFMap wrappers from UPF_XDPProgram.
   * Replaces old constructor map injection.
   * @throws std::invalid_argument if any pointer is null.
   */
  void SetMaps(
      std::shared_ptr<BPFMap> session_pdrs_map,
      std::shared_ptr<BPFMap> rules_match_map,
      std::shared_ptr<BPFMap> sdf_filter_map);

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
  // Map accessors
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
  // ==========================================================================
  // Private helpers
  // ==========================================================================
  /**
   * @brief Initialize BPF map wrappers
   */
  void InitializeMaps();

  /**
   * @brief Configure specific BPF maps
   *
   * @param skel Opened BPF skeleton
   * @param upf_cfg Configuration
   */
  void ConfigurePdrMatchMaps(struct pdr_match_kern_c* skel);

  /** @brief Build a pdr_map_key from SEID and PDR_ID (pad zeroed). */
  static pdr_rule_key MakePdrKey(uint64_t seid, uint32_t pdr_id);

  /** @brief Translate PFCP PDR IE into BPF pfcp_pdr struct. */
  static void ConvertPdr(
      const pfcp::pfcp_pdr& pfcp_ie, struct pfcp_pdr& bpf_pdr);

  // ==========================================================================
  // Skeleton and lifecycle
  // ==========================================================================
  xdp_pdr_match_kern_c* skeleton_ = nullptr;
  std::shared_ptr<PdrMatchProgramLifeCycle> lifecycle_;

  // ==========================================================================
  // Maps
  // ==========================================================================
  std::shared_ptr<BPFMaps> maps_;             ///< All BPF maps
  std::shared_ptr<BPFMap> session_pdrs_map_;  ///< PDR arrays per session
  std::shared_ptr<BPFMap> rules_match_map_;   ///< PDR → rule associations
  std::shared_ptr<BPFMap> sdf_filter_map_;    ///< SDF 5-tuple filter defs
};

#endif /* PDR_MATCH_USER_H_ */
