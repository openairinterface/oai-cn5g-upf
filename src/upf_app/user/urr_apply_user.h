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
 * Changes:     V17.10.0 audit -- fixed all §-refs in @see and struct
 *              comments (see urr_xdp_user.h history for full detail).
 *              Renamed urr_xdp_user.h -> urr_apply_user.h to mirror
 *              kernel file naming (xdp_urr_apply.c -> urr_apply_user.h).
 *              Added skeleton ownership following the QERProgram pattern:
 *                - URRProgram now owns xdp_urr_apply_c skeleton +
 *                  ProgramLifeCycle<xdp_urr_apply_c>.
 *                - SetMaps() replaces old constructor map injection so
 *                  UPF_XDPProgram can share map FDs after load.
 *              All existing map management methods preserved unchanged.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) -- PFCP Protocol
 */
// clang-format on

/**
 * @file  urr_apply_user.h
 * @brief User-space manager for URR (Usage Reporting Rule) BPF maps.
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * URRProgram owns the xdp_urr_apply_c BPF skeleton and manages the BPF maps
 * that back the XDP tail-call program `xdp_urr_apply` (PROG_URR_APPLY slot,
 * index 5 in tail_call_progs_map).
 *
 * Skeleton Lifecycle (driven by UPF_XDPProgram)
 * --------------------------------------------------
 *   1. URRProgram() constructor -- opens xdp_urr_apply_c skeleton.
 *   2. UPF_XDPProgram::ShareMapsFromPrimary() -- reuses primary map FDs.
 *   3. Load()    -- loads skeleton (map FDs already shared).
 *   4. SetMaps() -- receives BPFMap wrappers from UPF_XDPProgram.
 *   5. GetXdpProgram() -- provides program FD for tail_call_progs_map slot.
 *   6. Destructor -- destroys skeleton via ProgramLifeCycle.
 *
 * BPF Maps managed
 * ----------------
 *   urr_config_map          -- URR configuration per SEID.
 *                              Written by control plane; read by
 * xdp_urr_apply.c. Flags: BPF_ANY on create/modify; BPF_EXIST on update.
 *
 *   urr_volume_counters_map -- Per-SEID volume and packet counters.
 *                              Written atomically by data plane; read by
 * control plane for usage reporting. Initialised with BPF_NOEXIST so existing
 * counters are NEVER reset on modification.
 *
 * Lifecycle (session management)
 * --------------------------------
 *   UPF_XDPProgram::Setup() -> URRProgram constructed with skeleton
 *   SessionProgramManager::CreateSession() -> Setup(seid, urrs)
 *   SessionProgramManager::ModifySession() -> Update(seid, urr)
 *   SessionProgramManager::DeleteSession() -> TearDown(seid, urrs)
 *
 * @see 3GPP TS 29.244 §7.5.2.6  -- Create URR grouped IE
 * @see 3GPP TS 29.244 §8.2.54   -- URR ID
 * @see 3GPP TS 29.244 §8.2.48   -- Volume Threshold
 * @see 3GPP TS 29.244 §8.2.46   -- Volume Quota
 * @see 3GPP TS 29.244 §8.2.67   -- Monitoring Time
 * @see kernel/xdp/xdp_urr_apply.c -- BPF tail-call program
 */

#ifndef URR_APPLY_USER_H_
#define URR_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <xdp_urr_apply_skel.h>
#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <wrappers/BPFMap.hpp>
#include "BPFProgram.h"
#include <pfcp_urr.h>       /* struct pfcp_urr (shared kernel/user struct)  */
#include <pfcp_session.hpp> /* pfcp::pfcp_urr (PFCP IE wrapper)             */

/* Forward declaration */
class BPFMaps;
class BPFMap;

/* ==========================================================================
 * Type alias
 * ========================================================================== */

using UrrProgramLifeCycle = ProgramLifeCycle<xdp_urr_apply_kern_c>;

/* ==========================================================================
 * Map key type
 * ========================================================================== */

/**
 * @struct urr_map_key
 * @brief Compound BPF map key for urr_config_map and urr_volume_counters_map.
 *
 * Combines SEID and URR_ID into a 16-byte key so the same URR_ID can be
 * reused across different sessions without collision.
 * Must match the key definition in xdp_urr_apply.c.
 */
struct urr_map_key {
  uint64_t seid;    ///< PFCP Session Endpoint Identifier
  uint32_t urr_id;  ///< URR identifier (§8.2.54)
  uint32_t _pad;    ///< Alignment pad (must be zero)
} __attribute__((packed));

/* ==========================================================================
 * Volume counter type (runtime state, written by data plane)
 * ========================================================================== */

/**
 * @struct urr_volume_t
 * @brief Per-URR volume and packet counters maintained by the data plane.
 *
 * Stored in urr_volume_counters_map with BPF_NOEXIST semantics -- the control
 * plane only initialises these counters and NEVER resets them during
 * modification, preserving in-flight accounting across session updates.
 *
 * The control plane reads these values for:
 *   - Usage reporting (3GPP TS 29.244 §7.5.5 -- Usage Report)
 *   - Threshold/quota comparison (URR trigger evaluation)
 *
 * @see 3GPP TS 29.244 §8.2.48 -- Volume Threshold IE
 * @see 3GPP TS 29.244 §8.2.46 -- Volume Quota IE
 */
struct urr_volume_t {
  uint64_t total_bytes;  ///< Accumulated total bytes (UL + DL)
  uint64_t ul_bytes;     ///< Accumulated uplink bytes
  uint64_t dl_bytes;     ///< Accumulated downlink bytes
  uint64_t total_pkts;   ///< Accumulated total packets
  uint64_t ul_pkts;      ///< Accumulated uplink packets
  uint64_t dl_pkts;      ///< Accumulated downlink packets
};

/* ==========================================================================
 * URRProgram
 * ========================================================================== */

/**
 * @class URRProgram
 * @brief Skeleton owner and BPF map manager for URR XDP processing.
 *
 * Owns the xdp_urr_apply_c skeleton and translates PFCP URR IEs into
 * pfcp_urr BPF structs for the data plane.
 *
 * Thread Safety: Not thread-safe. External locking required when called
 * from SessionProgramManager (protected by sessions_mutex_).
 *
 * @see xdp_urr_apply.c -- corresponding BPF program
 */
class URRProgram : public BPFProgram {
 public:
  // ==========================================================================
  // Constructor / Destructor
  // ==========================================================================

  /**
   * @brief Constructor -- opens xdp_urr_apply skeleton.
   * Does NOT load the skeleton; call Load() after UPF_XDPProgram has
   * called ShareMapsFromPrimary() on this program's BPF object.
   * @throws std::runtime_error if skeleton open fails.
   */
  URRProgram();
  virtual ~URRProgram() = default;

  // ==========================================================================
  // Skeleton lifecycle
  // ==========================================================================

  /**
   * @brief Load the skeleton (call after map sharing is complete).
   * @throws std::runtime_error if load fails.
   */
  void Load();

  /**
   * @brief Return the underlying BPF object (for map sharing).
   * Used by UPF_XDPProgram::ShareMapsFromPrimary().
   */
  struct bpf_object* GetBpfObject() const;

  /**
   * @brief Return the XDP program pointer for tail_call_progs_map insertion.
   * Used by UPF_XDPProgram::InsertProgramSlot(PROG_URR_APPLY).
   */
  struct bpf_program* GetXdpProgram() const;

  // ==========================================================================
  // Map injection
  // ==========================================================================

  /**
   * @brief Receive BPFMap wrappers from UPF_XDPProgram.
   *
   * Called by UPF_XDPProgram::InitializeMaps() after the primary skeleton
   * is loaded and BPFMap objects have been wrapped around the shared FDs.
   * Replaces the old constructor map injection pattern.
   *
   * @param urr_config_map          Map storing pfcp_urr config per SEID.
   * @param urr_volume_counters_map Map storing volume counters per SEID.
   * @throws std::invalid_argument if either pointer is null.
   */
  void SetMaps(
      std::shared_ptr<BPFMap> urr_config_map,
      std::shared_ptr<BPFMap> urr_volume_counters_map);

  // ==========================================================================
  // Session lifecycle
  // ==========================================================================

  /**
   * @brief Configure all URRs for a new session.
   *
   * Populates urr_config_map and initialises urr_volume_counters_map for each
   * URR in the list. Volume counters are inserted with BPF_NOEXIST so they
   * start at zero without overwriting any existing data.
   *
   * @param seid  PFCP session identifier.
   * @param urrs  URR IEs from PFCP Session Establishment Request.
   * @see 3GPP TS 29.244 §7.5.2 -- PFCP Session Establishment Request
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_urr>>& urrs);

  /**
   * @brief Update a single URR for an existing session.
   *
   * Overwrites the config entry (BPF_EXIST) without touching the
   * volume counters in urr_volume_counters_map.
   *
   * @param seid  PFCP session identifier.
   * @param urr   Updated URR IE from PFCP Session Modification Request.
   * @see 3GPP TS 29.244 §7.5.4 -- PFCP Session Modification Request
   */
  void Update(uint64_t seid, const std::shared_ptr<pfcp::pfcp_urr>& urr);

  /**
   * @brief Remove a single URR from all maps.
   * @param seid    PFCP session identifier.
   * @param urr_id  URR identifier to remove.
   */
  void Remove(uint64_t seid, uint32_t urr_id);

  /**
   * @brief Tear down all URRs for a session on deletion.
   *
   * Does NOT send usage reports -- caller (SessionManager) is responsible
   * for collecting final usage before calling TearDown().
   *
   * @param seid  PFCP session identifier.
   * @param urrs  URRs to remove.
   * @see 3GPP TS 29.244 §7.5.6 -- PFCP Session Deletion Request
   */
  void TearDown(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_urr>>& urrs);

  // ==========================================================================
  // Map population helpers
  // ==========================================================================

  /**
   * @brief Populate urr_config_map for a single URR.
   * @param seid   PFCP session identifier.
   * @param urr    URR IE to convert and write.
   * @param flags  BPF_ANY / BPF_NOEXIST / BPF_EXIST.
   * @see struct pfcp_urr in pfcp_urr.h
   */
  void PopulateUrrConfigMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_urr>& urr,
      uint64_t flags = BPF_ANY);

  /**
   * @brief Initialise urr_volume_counters_map entry (BPF_NOEXIST).
   *
   * Creates a zero-initialised counter entry only if it does not already
   * exist, preserving any in-flight accounting across session updates.
   *
   * @param seid    PFCP session identifier.
   * @param urr_id  URR identifier.
   */
  void InitUrrVolumeMap(uint64_t seid, uint32_t urr_id);

  /**
   * @brief Read current volume counters for a URR.
   * @param seid    PFCP session identifier.
   * @param urr_id  URR identifier.
   * @param[out] volume  Output volume counter struct.
   * @return true if entry found and populated.
   */
  bool ReadVolumeCounters(
      uint64_t seid, uint32_t urr_id, urr_volume_t& volume) const;

  // ==========================================================================
  // Map accessors
  // ==========================================================================

  /** @return Shared pointer to urr_config_map. */
  std::shared_ptr<BPFMap> GetUrrConfigMap() const { return urr_config_map_; }

  /** @return Shared pointer to urr_volume_counters_map. */
  std::shared_ptr<BPFMap> GetUrrVolumeMap() const {
    return urr_volume_counters_map_;
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
  void ConfigureUrrMaps(struct urr_apply_kern_c* skel);

  /**
   * @brief Build URR ID to PDR mapping
   *
   * Creates internal map for quick PDR lookup by URR ID.
   *
   * @param pdrs Vector of PDRs
   */
  void BuildPdrMap(const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs);

  /**
   * @brief Get PDR associated with a URR ID
   *
   * @param urr_id URR identifier
   * @return std::shared_ptr<pfcp::pfcp_pdr> PDR or nullptr
   */
  std::shared_ptr<pfcp::pfcp_pdr> GetPdrByUrrId(uint32_t urr_id) const;

  /** @brief Build a urr_map_key from SEID and URR_ID (pad zeroed). */
  static urr_map_key MakeKey(uint64_t seid, uint32_t urr_id);

  /** @brief Translate PFCP URR IE into BPF pfcp_urr struct. */
  static void ConvertUrr(
      const pfcp::pfcp_urr& pfcp_ie, struct pfcp_urr& bpf_urr);

  // ==========================================================================
  // Skeleton and lifecycle
  // ==========================================================================
  xdp_urr_apply_kern_c* skeleton_ = nullptr;        ///< BPF skeleton
  std::shared_ptr<UrrProgramLifeCycle> lifecycle_;  ///< Lifecycle manager

  // ==========================================================================
  // Maps
  // ==========================================================================
  std::shared_ptr<BPFMaps> maps_;                    ///< All BPF maps
  std::shared_ptr<BPFMap> urr_config_map_;           ///< URR configuration map
  std::shared_ptr<BPFMap> urr_volume_counters_map_;  ///< URR volume counter map
};

#endif /* URR_APPLY_USER_H_ */