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
 * Changes:     V17.10.0 audit -- fixed all §-refs in @see, Steering Modes
 *              comment and struct field comments (see mar_xdp_user.h history
 *              for full detail).
 *              Renamed mar_xdp_user.h -> mar_apply_user.h to mirror
 *              kernel file naming (xdp_mar_apply.c -> mar_apply_user.h).
 *              Added skeleton ownership following the QERProgram pattern:
 *                - MARProgram now owns xdp_mar_apply_c skeleton +
 *                  ProgramLifeCycle<xdp_mar_apply_c>.
 *                - SetMaps() replaces old constructor map injection so
 *                  UPF_XDPProgram can share map FDs after load.
 *              All existing map management methods preserved unchanged.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) -- PFCP Protocol
 */
// clang-format on

/**
 * @file  mar_apply_user.h
 * @brief User-space manager for MAR (Multi-Access Rule) BPF maps.
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * MARProgram owns the xdp_mar_apply_c BPF skeleton and manages the BPF maps
 * that back the XDP tail-call program `xdp_mar_apply` (PROG_MAR_APPLY slot,
 * index 7 in tail_call_progs_map).
 *
 * MAR implements ATSSS (Access Traffic Steering, Switching and Splitting)
 * which is the 5G mechanism for distributing traffic across 3GPP (N3) and
 * non-3GPP (N9/WLAN) accesses simultaneously.
 *
 * Skeleton Lifecycle (driven by UPF_XDPProgram)
 * --------------------------------------------------
 *   1. MARProgram() constructor -- opens xdp_mar_apply_c skeleton.
 *   2. UPF_XDPProgram::ShareMapsFromPrimary() -- reuses primary map FDs.
 *   3. Load()    -- loads skeleton (map FDs already shared).
 *   4. SetMaps() -- receives BPFMap wrappers from UPF_XDPProgram.
 *   5. GetXdpProgram() -- provides program FD for tail_call_progs_map slot.
 *   6. Destructor -- destroys skeleton via ProgramLifeCycle.
 *
 * BPF Maps managed
 * ----------------
 *   mar_config_map        -- MAR steering configuration per SEID.
 *                            Written by control plane; read by xdp_mar_apply.c.
 *                            Stores pfcp_mar: steering mode + access FAR IDs.
 *
 *   mar_access_state_map  -- Per-SEID access-path RTT and liveness state.
 *                            Updated by userspace probe daemon.
 *                            Read by xdp_mar_apply.c for steering decisions.
 *
 * Steering Modes (3GPP TS 29.244 §8.2.125 Steering Mode)
 * -------------------------------------------------------
 *   STEER_ACTIVE_STANDBY : traffic to active access, failover to standby
 *   STEER_SMALLEST_DELAY : traffic to access with smaller RTT
 *   STEER_LOAD_BALANCE   : traffic split across both accesses
 *   STEER_PRIORITY_BASED : traffic to highest-priority access
 *
 * @see 3GPP TS 29.244 §7.5.2.8  -- Create MAR grouped IE
 * @see 3GPP TS 29.244 §8.2.123  -- MAR ID
 * @see 3GPP TS 29.244 §8.2.125  -- Steering Mode
 * @see 3GPP TS 29.244 §8.2.126  -- Weight (AFAI)
 * @see 3GPP TS 29.244 §8.2.127  -- Priority (AFAI)
 * @see 3GPP TS 23.501 §5.32     -- ATSSS
 * @see kernel/xdp/xdp_mar_apply.c -- BPF tail-call program
 */

#ifndef MAR_APPLY_USER_H_
#define MAR_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <xdp_mar_apply_skel.h>
#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <wrappers/BPFMap.hpp>
#include "BPFProgram.h"
#include <pfcp_mar.h>       /* struct pfcp_mar (shared kernel/user struct)  */
#include <pfcp_session.hpp> /* pfcp::pfcp_mar (PFCP IE wrapper)             */

/* Forward declaration */
class BPFMap;
class BPFMaps;

/* ==========================================================================
 * Type alias
 * ========================================================================== */

using MarProgramLifeCycle = ProgramLifeCycle<xdp_mar_apply_kern_c>;

/* ==========================================================================
 * Map key type
 * ========================================================================== */

/**
 * @struct mar_map_key
 * @brief Compound BPF map key for mar_config_map and mar_access_state_map.
 * Must match the key definition in xdp_mar_apply.c.
 */
struct mar_map_key {
  uint64_t seid;    ///< PFCP Session Endpoint Identifier
  uint32_t mar_id;  ///< MAR identifier (§8.2.123)
  uint32_t _pad;    ///< Alignment pad (must be zero)
} __attribute__((packed));

/* ==========================================================================
 * MARProgram
 * ========================================================================== */

/**
 * @class MARProgram
 * @brief Skeleton owner and BPF map manager for MAR XDP processing.
 *
 * Owns the xdp_mar_apply_c skeleton and translates PFCP MAR IEs into
 * pfcp_mar BPF structs for the data plane.
 *
 * The BPF data plane uses steer_mode, active_access / standby_access, and
 * access FAR IDs to implement ATSSS packet steering with no control-plane
 * involvement in the fast path.
 *
 * Thread Safety: Not thread-safe. External locking required.
 *
 * @see xdp_mar_apply.c -- corresponding BPF program
 */
class MARProgram : public BPFProgram {
 public:
  // ==========================================================================
  // Constructor / Destructor
  // ==========================================================================

  /**
   * @brief Constructor -- opens xdp_mar_apply skeleton.
   * @throws std::runtime_error if skeleton open fails.
   */
  MARProgram();
  virtual ~MARProgram() = default;

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
   * @param mar_config_map       Map storing pfcp_mar config per SEID.
   * @param mar_access_state_map Map storing RTT/liveness state per SEID.
   * @throws std::invalid_argument if mar_config_map is null.
   */
  void SetMaps(
      std::shared_ptr<BPFMap> mar_config_map,
      std::shared_ptr<BPFMap> mar_access_state_map);

  // ==========================================================================
  // Session lifecycle
  // ==========================================================================

  /**
   * @brief Configure all MARs for a new session.
   * @param seid  PFCP session identifier.
   * @param mars  MAR IEs from PFCP Session Establishment Request.
   * @see 3GPP TS 29.244 §7.5.2 -- PFCP Session Establishment Request
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_mar>>& mars);

  /**
   * @brief Update a single MAR for an existing session.
   * @param seid  PFCP session identifier.
   * @param mar   Updated MAR IE from PFCP Session Modification Request.
   * @see 3GPP TS 29.244 §7.5.4 -- PFCP Session Modification Request
   */
  void Update(uint64_t seid, const std::shared_ptr<pfcp::pfcp_mar>& mar);

  /**
   * @brief Remove a single MAR from all maps.
   * @param seid    PFCP session identifier.
   * @param mar_id  MAR identifier to remove.
   */
  void Remove(uint64_t seid, uint32_t mar_id);

  /**
   * @brief Tear down all MARs for a session on deletion.
   * @param seid  PFCP session identifier.
   * @param mars  MARs to remove.
   */
  void TearDown(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_mar>>& mars);

  // ==========================================================================
  // Map population helpers
  // ==========================================================================

  /**
   * @brief Populate mar_config_map for a single MAR.
   * @param seid   PFCP session identifier.
   * @param mar    MAR IE to convert and write.
   * @param flags  BPF_ANY / BPF_NOEXIST / BPF_EXIST.
   * @see struct pfcp_mar in pfcp_mar.h
   */
  void PopulateMarRulesMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_mar>& mar,
      uint64_t flags = BPF_ANY);

  // ==========================================================================
  // Map accessors
  // ==========================================================================

  /** @return Shared pointer to mar_config_map. */
  std::shared_ptr<BPFMap> GetMarConfigMap() const { return mar_config_map_; }

  /** @return Shared pointer to mar_access_state_map. */
  std::shared_ptr<BPFMap> GetMarAccessStateMap() const {
    return mar_access_state_map_;
  }

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
  void ConfigureMarMaps(struct mar_apply_kern_c* skel);

  /**
   * @brief Build MAR ID to PDR mapping
   *
   * Creates internal map for quick PDR lookup by MAR ID.
   *
   * @param pdrs Vector of PDRs
   */
  void BuildPdrMap(const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs);

  /**
   * @brief Get PDR associated with a MAR ID
   *
   * @param mar_id MAR identifier
   * @return std::shared_ptr<pfcp::pfcp_pdr> PDR or nullptr
   */
  std::shared_ptr<pfcp::pfcp_pdr> GetPdrByMarId(uint32_t mar_id) const;

  /** @brief Build a mar_map_key from SEID and MAR_ID (pad zeroed). */
  static mar_map_key MakeKey(uint64_t seid, uint32_t mar_id);

  /** @brief Translate PFCP MAR IE into BPF pfcp_mar struct. */
  static void ConvertMar(const pfcp::pfcp_mar& ie, struct pfcp_mar& bpf_mar);

  // ==========================================================================
  // Skeleton and lifecycle
  // ==========================================================================
  xdp_mar_apply_kern_c* skeleton_ = nullptr;        ///< BPF skeleton
  std::shared_ptr<MarProgramLifeCycle> lifecycle_;  ///< Lifecycle manager

  // ==========================================================================
  // Maps
  // ==========================================================================
  std::shared_ptr<BPFMaps> maps_;                 ///< All BPF maps
  std::shared_ptr<BPFMap> mar_config_map_;        ///< MAR steering config map
  std::shared_ptr<BPFMap> mar_access_state_map_;  ///< MAR path RTT/liveness map
};

#endif /* MAR_APPLY_USER_H_ */