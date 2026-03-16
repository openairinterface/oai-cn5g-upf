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
 * Changes:     V17.10.0 audit — Boy Scout pass:
 *                - Fixed two wrong §-refs in @file block:
 *                    §7.2.2 (does not exist in TS 29.244) → §7.5.2
 *                      (PFCP Session Establishment Request)
 *                    §7.2.4 (does not exist in TS 29.244) → §7.5.4
 *                      (PFCP Session Modification Request)
 *                - Removed `virtual` from ~SessionPrograms().  The class
 *                  has no subclasses and is stored by value in
 *                  SessionProgramManager::session_programs_map_; the
 *                  virtual keyword forced an unnecessary vtable.  Same
 *                  pattern fixed in SignalHandler.
 *                - Removed vacuous `@note Follows Google C++ Style Guide`.
 *                - Added changelog block with clang-format guards.
 *                - Updated @author / @date.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/**
 * @file SessionPrograms.h
 * @brief Per-session BPF program and rule state container
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * Container for all BPF-related state associated with a single PFCP session.
 * In the tail-call architecture the XDP pipeline is shared across all
 * sessions (single UPF_XDPProgram manages the global PROG_ARRAY), while
 * per-session state lives in BPF maps keyed by SEID.
 *
 * Ownership model:
 *   - UPF_XDPProgram: NON-OWNING reference (global pipeline, shared by all
 *     sessions).  Provides access to BPF maps for per-session entries.
 *     MUST NOT be torn down when a session is destroyed.
 *   - QERProgram: OWNING reference (per-session TC-BPF for rate shaping).
 *     Created when QER rules are present, torn down with the session.
 *
 * Per-session BPF map entries (managed by SessionProgramManager):
 *   - session_by_ue_ip_map   : UE IP  → session_id  (IP PDU sessions)
 *   - session_by_mac_map     : MAC    → session_id  (ETH PDU sessions)
 *   - pdrs_per_session_map   : SEID   → PDR array
 *   - rules_match_pdr_map    : SEID   → rule match state
 *   - session_rules_enabled_map: SEID → bitmask (RULE_QER|URR|BAR|MAR)
 *   - urr_config_map         : SEID   → pfcp_urr_t (usage reporting config)
 *   - urr_volume_map         : SEID   → urr_volume_t (runtime counters)
 *   - bar_config_map         : SEID   → pfcp_bar_t (buffering config)
 *   - bar_state_map          : SEID   → bar_state_t (runtime state)
 *   - mar_rules_map          : SEID   → pfcp_mar_t (ATSSS steering rules)
 *
 * Feature enable tracking:
 *   Each session carries a rules_enabled bitmask (from rules_enabled_flags.h)
 *   that tells the BPF skip-chain which tail calls to invoke.  The bitmask
 *   is written to session_rules_enabled_map during session establishment
 *   and updated during modification.
 *
 * Lifecycle (managed by SessionProgramManager):
 *   1. Construction    : SEID + pipeline reference
 *   2. PopulateMaps    : Write PDRs, FARs, QERs, URRs, BARs, MARs to BPF maps
 *   3. SetQERProgram   : Attach TC-BPF if QER rules present
 *   4. UpdateMaps      : Modify rules on PFCP Session Modification (§7.5.4)
 *   5. Destruction     : Tear down TC-BPF + remove per-session BPF map entries
 *
 * @see 3GPP TS 29.244 V17.10.0 §7.5.2  PFCP Session Establishment Request
 * @see 3GPP TS 29.244 V17.10.0 §7.5.4  PFCP Session Modification Request
 * @see rules_enabled_flags.h — bitmask flag definitions
 * @see tail_call_dispatch.h  — program slot definitions
 */

#ifndef SESSION_PROGRAMS_H_
#define SESSION_PROGRAMS_H_

#include <cstdint>
#include <memory>

// Forward declarations — avoid circular includes
class UPF_XDPProgram;
class QERProgram;

/**
 * @class SessionPrograms
 * @brief Per-session BPF program and rule state container.
 *
 * Each PFCP session (identified by SEID) gets one SessionPrograms instance
 * stored in SessionProgramManager::session_programs_map_.  This container
 * provides:
 *
 *   1. Access to the global XDP pipeline (for BPF map operations)
 *   2. Ownership of the per-session QER TC-BPF program
 *   3. Tracking of which rules are active (QER / URR / BAR / MAR bitmask)
 *
 * The rules_enabled bitmask mirrors what is written to the BPF
 * session_rules_enabled_map, allowing userspace to check active features
 * without reading the BPF map.
 *
 * Thread safety: not thread-safe; access is serialised by
 * SessionProgramManager.
 *
 * @note Non-virtual destructor — this class is not designed for subclassing.
 */
class SessionPrograms {
 public:
  /**
   * @brief Construct a session program container.
   *
   * @param seid            PFCP Session Endpoint Identifier (unique key).
   * @param upf_xdp_program Non-owning reference to the global XDP pipeline.
   *                        Used to access BPF maps for per-session entries.
   *                        MUST outlive this SessionPrograms instance.
   */
  SessionPrograms(
      uint64_t seid, std::shared_ptr<UPF_XDPProgram> upf_xdp_program);

  /**
   * @brief Destructor — tears down per-session resources only.
   *
   * Cleanup order (ordering is significant — see SessionPrograms.cpp):
   *   1. Tear down QERProgram (TC-BPF rate shaping classes) — must precede
   *      BPF map cleanup so QER map entries still exist for TearDown().
   *   2. Remove per-session BPF map entries:
   *        urr_config_map, urr_volume_map  (if URR enabled)
   *        bar_config_map, bar_state_map   (if BAR enabled)
   *        mar_rules_map                   (if MAR enabled)
   *        session_rules_enabled_map       (always)
   *
   * @note Does NOT tear down UPF_XDPProgram (global shared pipeline).
   */
  ~SessionPrograms();

  // ==========================================================================
  // Identity
  // ==========================================================================

  /** @brief Return the PFCP Session Endpoint Identifier. */
  uint64_t GetSeid() const;

  // ==========================================================================
  // Pipeline access (non-owning)
  // ==========================================================================

  /**
   * @brief Return a reference to the global XDP pipeline program.
   *
   * Provides access to shared BPF maps for per-session operations.
   *
   * @return Shared pointer to the global UPF_XDPProgram (non-owning).
   * @warning Do NOT call TearDown() on the returned pointer — the pipeline
   *          is shared across all active sessions.
   */
  std::shared_ptr<UPF_XDPProgram> GetPipelineProgram() const;

  // ==========================================================================
  // QER program (per-session, owning)
  // ==========================================================================

  /**
   * @brief Attach a QER TC-BPF program to this session.
   *
   * The QER program manages per-session TC HTB classes for MBR/GBR rate
   * shaping (3GPP TS 29.244 V17.10.0 §8.2.8 MBR / §8.2.9 GBR).
   * One QERProgram per session.  Ownership is transferred — the program
   * is torn down in the destructor.
   *
   * @param qer_program Shared pointer to the TC-BPF QER program.
   */
  void SetQERProgram(std::shared_ptr<QERProgram> qer_program);

  /**
   * @brief Return the QER TC-BPF program for this session.
   * @return Shared pointer to the QER program, or nullptr if none.
   */
  std::shared_ptr<QERProgram> GetQERProgram() const;

  /** @brief Return true if a QER TC-BPF program is attached. */
  bool HasQERProgram() const;

  // ==========================================================================
  // Per-session rule enable flags
  // ==========================================================================

  /**
   * @brief Set the rules_enabled bitmask for this session.
   *
   * Called by SessionProgramManager during session establishment (§7.5.2)
   * and modification (§7.5.4).  The same value is written to the BPF
   * session_rules_enabled_map for skip-chain dispatch.
   *
   * @param flags  OR of RULE_QER_ENABLED | RULE_URR_ENABLED |
   *               RULE_BAR_ENABLED | RULE_MAR_ENABLED.
   * @see rules_enabled_flags.h
   */
  void SetRulesEnabledFlags(uint32_t flags);

  /** @brief Return the current rules_enabled bitmask. */
  uint32_t GetRulesEnabledFlags() const;

  /**
   * @brief Return true if the given rule type flag is set.
   * @param flag  Single flag, e.g. RULE_URR_ENABLED.
   */
  bool IsRuleEnabled(uint32_t flag) const;

  // ==========================================================================
  // Convenience accessors
  // ==========================================================================

  /** @brief Return true if QER is enabled in the BPF skip-chain. */
  bool IsQEREnabled() const;

  /** @brief Return true if URR is enabled in the BPF skip-chain. */
  bool IsURREnabled() const;

  /** @brief Return true if BAR is enabled in the BPF skip-chain. */
  bool IsBAREnabled() const;

  /** @brief Return true if MAR is enabled in the BPF skip-chain. */
  bool IsMAREnabled() const;

 private:
  /**
   * @brief Remove per-session entries from all relevant BPF maps.
   *
   * Called by the destructor after QERProgram has been torn down.
   * Only touches maps for rule types that were actually enabled
   * (checked via the rules_enabled bitmask).
   */
  void CleanupBpfMapEntries();

  uint64_t seid_;  ///< PFCP Session Endpoint Identifier (§8.2.37)

  /// Global XDP pipeline reference (NON-OWNING — shared across all sessions).
  /// Provides access to BPF maps.  NEVER call TearDown() on this.
  std::shared_ptr<UPF_XDPProgram> upf_xdp_program_;

  /// Per-session QER TC-BPF program (OWNING — torn down in destructor).
  /// Manages HTB qdisc classes for MBR/GBR rate shaping (§8.2.8 / §8.2.9).
  std::shared_ptr<QERProgram> qer_program_;

  /// Per-session bitmask of enabled rules (mirrors BPF map entry).
  /// @see rules_enabled_flags.h
  uint32_t rules_enabled_flags_;
};

#endif  // SESSION_PROGRAMS_H_
