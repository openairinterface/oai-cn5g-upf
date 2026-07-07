/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef SESSION_PROGRAMS_H_
#define SESSION_PROGRAMS_H_

#include <cstdint>
#include <memory>

// Forward declarations — avoid circular includes
class UPF_XDPProgram;
class QERTCProgram;

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
   *   1. Tear down QERTCProgram (TC-BPF rate shaping classes) — must precede
   *      BPF map cleanup so QER map entries still exist for TearDown().
   *   2. Remove per-session BPF map entries:
   *        urr_config_map, urr_volume_counters_map  (if URR enabled)
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
   * One QERTCProgram per session.  Ownership is transferred — the program
   * is torn down in the destructor.
   *
   * @param qer_program Shared pointer to the TC-BPF QER program.
   */
  void SetQERProgram(std::shared_ptr<QERTCProgram> qer_program);

  /**
   * @brief Return the QER TC-BPF program for this session.
   * @return Shared pointer to the QER program, or nullptr if none.
   */
  std::shared_ptr<QERTCProgram> GetQERProgram() const;

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
   * Called by the destructor after QERTCProgram has been torn down.
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
  std::shared_ptr<QERTCProgram> qer_program_;

  /// Per-session bitmask of enabled rules (mirrors BPF map entry).
  /// @see rules_enabled_flags.h
  uint32_t rules_enabled_flags_;
};

#endif  // SESSION_PROGRAMS_H_
