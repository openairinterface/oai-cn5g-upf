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
 * Changes:     V17.10.0 audit -- fixed all §-refs in @see block and struct
 *              field comments (see bar_xdp_user.h history for full detail).
 *              Renamed bar_xdp_user.h -> bar_apply_user.h to mirror
 *              kernel file naming (xdp_bar_apply.c -> bar_apply_user.h).
 *              Added skeleton ownership following the QERProgram pattern:
 *                - BARProgram now owns xdp_bar_apply_c skeleton +
 *                  ProgramLifeCycle<xdp_bar_apply_c>.
 *                - SetMaps() replaces old constructor map injection so
 *                  UPF_XDPProgram can share map FDs after load.
 *              All existing map management methods preserved unchanged.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) -- PFCP Protocol
 */
// clang-format on

/**
 * @file  bar_apply_user.h
 * @brief User-space manager for BAR (Buffering Action Rule) BPF maps.
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * BARProgram owns the xdp_bar_apply_c BPF skeleton and manages the BPF maps
 * that back the XDP tail-call program `xdp_bar_apply` (PROG_BAR_APPLY slot,
 * index 6 in tail_call_progs_map).
 *
 * BAR is referenced indirectly: a FAR with apply_action.buff=1 carries a
 * BAR_ID that indexes into bar_config_map to control buffering behaviour.
 * This side path is terminal -- after buffering, no further tail calls.
 *
 * Skeleton Lifecycle (driven by UPF_XDPProgram)
 * --------------------------------------------------
 *   1. BARProgram() constructor -- opens xdp_bar_apply_c skeleton.
 *   2. UPF_XDPProgram::ShareMapsFromPrimary() -- reuses primary map FDs.
 *   3. Load()    -- loads skeleton (map FDs already shared).
 *   4. SetMaps() -- receives BPFMap wrappers from UPF_XDPProgram.
 *   5. GetXdpProgram() -- provides program FD for tail_call_progs_map slot.
 *   6. Destructor -- destroys skeleton via ProgramLifeCycle.
 *
 * BPF Maps managed
 * ----------------
 *   bar_config_map  -- BAR configuration per SEID.
 *                      Written by control plane; read by xdp_bar_apply.c.
 *                      Stores pfcp_bar: DDN delay + buffer packet count hint.
 *
 *   bar_state_map   -- Runtime buffering state per SEID.
 *                      Written atomically by data plane.
 *                      Stores: last DDN timestamp, buffered packet count,
 *                      notification-sent flag.
 *                      NEVER reset during modification -- state preserved
 *                      across session updates to avoid spurious DDN retrigger.
 *
 * DDN suppression logic
 * ---------------------
 *   dl_notification_delay_sec > 0: the data plane suppresses duplicate DDN
 *   notifications within the delay window (bar_state.last_ddn_ns).
 *   The control plane must NOT clear last_ddn_ns during modification --
 *   handled by BPF_NOEXIST state initialisation.
 *
 * @see 3GPP TS 29.244 §7.5.2.7  -- Create BAR grouped IE
 * @see 3GPP TS 29.244 §8.2.57   -- BAR ID
 * @see 3GPP TS 29.244 §8.2.100  -- Suggested Buffering Packets Count
 * @see 3GPP TS 29.244 §8.2.28   -- DL Data Notification Delay
 * @see kernel/xdp/xdp_bar_apply.c -- BPF tail-call program
 */

#ifndef BAR_APPLY_USER_H_
#define BAR_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <xdp_bar_apply_skel.h>
#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <wrappers/BPFMap.hpp>
#include "BPFProgram.h"
#include <pfcp_bar.h>       /* struct pfcp_bar (shared kernel/user struct)  */
#include <pfcp_session.hpp> /* pfcp::pfcp_bar (PFCP IE wrapper)             */

/* Forward declaration */
class BPFMap;
class BPFMaps;

/* ==========================================================================
 * Type alias
 * ========================================================================== */

using BarProgramLifeCycle = ProgramLifeCycle<xdp_bar_apply_kern_c>;

/* ==========================================================================
 * Map key type
 * ========================================================================== */

/**
 * @struct bar_map_key
 * @brief Compound BPF map key for bar_config_map and bar_state_map.
 * Must match the key definition in xdp_bar_apply.c.
 */
struct bar_map_key {
  uint64_t seid;    ///< PFCP Session Endpoint Identifier
  uint32_t bar_id;  ///< BAR identifier (§8.2.57)
  uint32_t _pad;    ///< Alignment pad (must be zero)
} __attribute__((packed));

/* ==========================================================================
 * Runtime buffering state (written by data plane)
 * ========================================================================== */

/**
 * @struct bar_state_t
 * @brief Per-BAR runtime buffering state maintained atomically by data plane.
 *
 * Initialised with BPF_NOEXIST on session creation so that existing state
 * is preserved across session modifications.
 *
 * @see 3GPP TS 29.244 §8.2.28 -- DL Data Notification Delay
 */
struct bar_state_t {
  uint64_t last_ddn_ns;         ///< bpf_ktime_get_ns() at last DDN send
  uint32_t buffered_pkt_count;  ///< DL packets buffered since last DDN
  uint8_t notification_sent;    ///< 1 if DDN already sent this window
  uint8_t _pad[3];
};

/* ==========================================================================
 * BARProgram
 * ========================================================================== */

/**
 * @class BARProgram
 * @brief Skeleton owner and BPF map manager for BAR XDP processing.
 *
 * Owns the xdp_bar_apply_c skeleton and translates PFCP BAR IEs into
 * pfcp_bar BPF structs for the data plane.
 *
 * Thread Safety: Not thread-safe. External locking required.
 *
 * @see xdp_bar_apply.c -- corresponding BPF program
 */
class BARProgram : public BPFProgram {
 public:
  // ==========================================================================
  // Constructor / Destructor
  // ==========================================================================

  /**
   * @brief Constructor -- opens xdp_bar_apply skeleton.
   * @throws std::runtime_error if skeleton open fails.
   */
  BARProgram();
  virtual ~BARProgram() = default;

  // ==========================================================================
  // Skeleton lifecycle
  // ==========================================================================

  /** @brief Load the skeleton (call after map sharing is complete). */
  void Load();

  /** @brief Return the underlying BPF object (for map sharing). */
  struct bpf_object* GetBpfObject() const;

  /** @brief Return the XDP program pointer for tail_call_progs_map insertion.
   */
  struct bpf_program* GetXdpProgram() const;

  // ==========================================================================
  // Map injection
  // ==========================================================================

  /**
   * @brief Receive BPFMap wrappers from UPF_XDPProgram.
   * @param bar_config_map  Map storing pfcp_bar config per SEID.
   * @param bar_state_map   Map storing runtime buffering state per SEID.
   * @throws std::invalid_argument if either pointer is null.
   */
  void SetMaps(
      std::shared_ptr<BPFMap> bar_config_map,
      std::shared_ptr<BPFMap> bar_state_map);

  // ==========================================================================
  // Session lifecycle
  // ==========================================================================

  /**
   * @brief Configure all BARs for a new session.
   *
   * Populates bar_config_map and initialises bar_state_map (BPF_NOEXIST)
   * for each BAR in the list.
   *
   * @param seid  PFCP session identifier.
   * @param bars  BAR IEs from PFCP Session Establishment Request.
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars);

  /**
   * @brief Update a single BAR for an existing session.
   *
   * Overwrites the config entry; bar_state_map is NOT touched so that DDN
   * suppression state and buffered packet count are preserved.
   *
   * @param seid  PFCP session identifier.
   * @param bar   Updated BAR IE from PFCP Session Modification Request.
   */
  void Update(uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar);

  /**
   * @brief Remove a single BAR from all maps.
   * @param seid    PFCP session identifier.
   * @param bar_id  BAR identifier to remove.
   */
  void Remove(uint64_t seid, uint32_t bar_id);

  /**
   * @brief Tear down all BARs for a session on deletion.
   * @param seid  PFCP session identifier.
   * @param bars  BARs to remove.
   */
  void TearDown(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars);

  // ==========================================================================
  // Map population helpers
  // ==========================================================================

  /**
   * @brief Populate bar_config_map for a single BAR.
   * @param seid   PFCP session identifier.
   * @param bar    BAR IE to convert and write.
   * @param flags  BPF_ANY / BPF_NOEXIST / BPF_EXIST.
   */
  void PopulateBarConfigMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar,
      uint64_t flags = BPF_ANY);

  /**
   * @brief Initialise bar_state_map entry (BPF_NOEXIST -- preserves state).
   * @param seid    PFCP session identifier.
   * @param bar_id  BAR identifier.
   */
  void InitBarStateMap(uint64_t seid, uint32_t bar_id);

  /**
   * @brief Read current buffering state for a BAR.
   * @param seid    PFCP session identifier.
   * @param bar_id  BAR identifier.
   * @param[out] state  Output state struct.
   * @return true if entry found.
   */
  bool ReadBarState(uint64_t seid, uint32_t bar_id, bar_state_t& state) const;

  // ==========================================================================
  // Map accessors
  // ==========================================================================

  /** @return Shared pointer to bar_config_map. */
  std::shared_ptr<BPFMap> GetBarConfigMap() const { return bar_config_map_; }

  /** @return Shared pointer to bar_state_map. */
  std::shared_ptr<BPFMap> GetBarStateMap() const { return bar_state_map_; }

 private:
  // ==========================================================================
  // Private helpers
  // ==========================================================================
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
  void ConfigureBarMaps(struct bar_apply_kern_c* skel);

  /**
   * @brief Build BAR ID to PDR mapping
   *
   * Creates internal map for quick PDR lookup by BAR ID.
   *
   * @param pdrs Vector of PDRs
   */
  void BuildPdrMap(const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs);

  /**
   * @brief Get PDR associated with a BAR ID
   *
   * @param bar_id BAR identifier
   * @return std::shared_ptr<pfcp::pfcp_pdr> PDR or nullptr
   */
  std::shared_ptr<pfcp::pfcp_pdr> GetPdrByBarId(uint32_t bar_id) const;

  /** @brief Build a bar_map_key from SEID and BAR_ID (pad zeroed). */
  static bar_map_key MakeKey(uint64_t seid, uint32_t bar_id);

  /** @brief Translate PFCP BAR IE into BPF pfcp_bar struct. */
  static void ConvertBar(const pfcp::pfcp_bar& ie, struct pfcp_bar& bpf_bar);

  // ==========================================================================
  // Skeleton and lifecycle
  // ==========================================================================
  xdp_bar_apply_kern_c* skeleton_ = nullptr;        ///< BPF skeleton
  std::shared_ptr<BarProgramLifeCycle> lifecycle_;  ///< Lifecycle manager

  // ==========================================================================
  // Maps
  // ==========================================================================
  std::shared_ptr<BPFMaps> maps_;           ///< All BPF maps
  std::shared_ptr<BPFMap> bar_config_map_;  ///< BAR configuration map
  std::shared_ptr<BPFMap> bar_state_map_;   ///< BAR runtime state map
};

#endif /* BAR_APPLY_USER_H_ */
