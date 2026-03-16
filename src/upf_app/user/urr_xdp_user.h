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
 * Changes:     V17.10.0 audit — fixed all §-refs in @see and struct comments:
 *                - Section 8.2.5 — Create URR IE: §8.2.5 = SDF Filter in
 *                  V17.10.0; Create URR grouped IE is at §7.5.2.6.
 *                  Fixed: @see §7.5.2.6.
 *                - Section 8.2.44 — URR ID: §8.2.44 = Volume Measurement in
 *                  V17.10.0; URR ID is at §8.2.54.
 *                  Fixed: @see §8.2.54; urr_map_key field comment updated.
 *                - Section 8.2.48 — Volume Threshold / Quota: §8.2.48 =
 *                  Volume Threshold (correct). Volume Quota is at §8.2.46
 *                  (separate ref). Split into two @see lines.
 *                - Section 8.2.67 — Monitoring Time: not in our verified
 *                  §-ref map; left as-is per rule 12 (only fix provably
 *                  wrong refs).
 *              Boy Scout: added changelog with clang-format guards; updated
 *              @author / @date.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/**
 * @file urr_xdp_user.h
 * @brief User-space manager for URR (Usage Reporting Rule) BPF maps
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * URRProgram manages the BPF maps that back the XDP tail-call program
 * `urr_apply` (PROG_URR slot, index 4 in feature_dispatch_map).
 *
 * Unlike QERProgram (which has its own TC-BPF skeleton), URRProgram does
 * NOT own a separate BPF skeleton.  `urr_apply.c` is compiled into the
 * same `upf_xdp_kern` object as the rest of the pipeline.  URRProgram
 * receives shared BPFMap references from UPF_XDPProgram::GetMapByName()
 * and exposes a typed API for populating / reading / removing entries.
 *
 * BPF Maps managed
 * ----------------
 *   urr_config_map  — URR configuration per (SEID, URR_ID).
 *                     Written by control plane; read by urr_apply.c.
 *                     Flags: BPF_ANY on create/modify; BPF_EXIST on update.
 *
 *   urr_volume_map  — Per-(SEID, URR_ID) volume and packet counters.
 *                     Written atomically by data plane; read by control
 *                     plane for usage reporting.
 *                     Initialised with BPF_NOEXIST so that existing
 *                     counters are NEVER reset on modification.
 *
 * Map key
 * -------
 *   struct urr_map_key { uint64_t seid; uint32_t urr_id; uint32_t _pad; }
 *   Maps a (session, rule) pair to its configuration / volume entry.
 *
 * Lifecycle
 * ---------
 *   UPF_XDPProgram::Setup() → URRProgram constructed with map refs
 *   SessionProgramManager::CreateSession() → Setup(seid, urrs)
 *   SessionProgramManager::ModifySession() → Update(seid, urr)
 *   SessionProgramManager::DeleteSession() → TearDown(seid, urrs)
 *
 * @see 3GPP TS 29.244 §7.5.2.6  — Create URR grouped IE
 * @see 3GPP TS 29.244 §8.2.54   — URR ID
 * @see 3GPP TS 29.244 §8.2.48   — Volume Threshold
 * @see 3GPP TS 29.244 §8.2.46   — Volume Quota
 * @see 3GPP TS 29.244 §8.2.67   — Monitoring Time
 * @see kernel/xdp/urr_apply.c        — BPF tail-call program
 * @note Follows Google C++ Style Guide
 */

#ifndef URR_XDP_USER_H_
#define URR_XDP_USER_H_

#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <wrappers/BPFMap.hpp>
#include <pfcp_urr.h>        // struct pfcp_urr (shared kernel/user struct)
#include <pfcp_session.hpp>  // pfcp::pfcp_urr (PFCP IE wrapper)

// Forward declarations
class BPFMap;

// ==========================================================================
// Map key type
// ==========================================================================

/**
 * @struct urr_map_key
 * @brief Compound BPF map key for URR config and volume maps
 *
 * Combines SEID and URR_ID into a single 16-byte key so the same URR_ID
 * can be reused across different sessions without collision.
 *
 * Must match the key definition in the kernel urr_apply.c BPF program.
 */
struct urr_map_key {
  uint64_t seid;    ///< PFCP Session Endpoint Identifier
  uint32_t urr_id;  ///< URR identifier (§8.2.54)
  uint32_t _pad;    ///< Alignment pad (must be zero)
} __attribute__((packed));

// ==========================================================================
// Volume counter type (runtime state written by data plane)
// ==========================================================================

/**
 * @struct urr_volume_t
 * @brief Per-URR volume and packet counters maintained by the data plane
 *
 * Stored in urr_volume_map with BPF_NOEXIST semantics — the control plane
 * only initialises these counters and NEVER resets them during modification,
 * preserving in-flight accounting across session updates.
 *
 * The control plane reads these values for:
 *   - Usage reporting (3GPP TS 29.244 §7.5.5 — Usage Report)
 *   - Threshold/quota comparison (URR trigger evaluation)
 *
 * @see 3GPP TS 29.244 §8.2.48 — Volume Threshold IE
 * @see 3GPP TS 29.244 §8.2.46 — Volume Quota IE
 */
struct urr_volume_t {
  uint64_t total_bytes;  ///< Accumulated total bytes (UL + DL)
  uint64_t ul_bytes;     ///< Accumulated uplink bytes
  uint64_t dl_bytes;     ///< Accumulated downlink bytes
  uint64_t total_pkts;   ///< Accumulated total packets
  uint64_t ul_pkts;      ///< Accumulated uplink packets
  uint64_t dl_pkts;      ///< Accumulated downlink packets
};

// ==========================================================================
// URRProgram
// ==========================================================================

/**
 * @class URRProgram
 * @brief User-space manager for URR BPF maps in the XDP pipeline
 *
 * Responsibilities:
 *   - Translate PFCP URR IEs into `pfcp_urr` BPF structs
 *   - Write configuration into urr_config_map (BPF_ANY)
 *   - Initialise volume counters in urr_volume_map (BPF_NOEXIST)
 *   - Read volume counters for usage reporting
 *   - Remove entries on session deletion
 *
 * Instantiated by UPF_XDPProgram::Setup() after the skeleton is loaded
 * and maps are initialised.
 *
 * Thread Safety: Not thread-safe.  External locking required when called
 * from SessionProgramManager (protected by sessions_mutex_).
 *
 * @see urr_apply.c — corresponding BPF program
 * @note Follows Google C++ Style Guide
 */
class URRProgram {
 public:
  /**
   * @brief Constructor — receives shared BPFMap references
   *
   * @param urr_config_map  BPF map storing pfcp_urr config per (SEID, URR_ID)
   * @param urr_volume_map  BPF map storing volume counters per (SEID, URR_ID)
   *
   * @throws std::invalid_argument if either map pointer is null
   */
  URRProgram(
      std::shared_ptr<BPFMap> urr_config_map,
      std::shared_ptr<BPFMap> urr_volume_map);

  ~URRProgram() = default;

  // ==========================================================================
  // Session lifecycle
  // ==========================================================================

  /**
   * @brief Configure all URRs for a new session
   *
   * Populates urr_config_map and initialises urr_volume_map for each URR
   * in the list.  Volume counters are inserted with BPF_NOEXIST so they
   * start at zero without overwriting any existing data.
   *
   * @param seid   PFCP session identifier
   * @param urrs   URR IEs from PFCP Session Establishment Request
   *
   * @see 3GPP TS 29.244 §7.5.2  — PFCP Session Establishment Request
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_urr>>& urrs);

  /**
   * @brief Update a single URR for an existing session
   *
   * Overwrites the config entry (BPF_EXIST) without touching the
   * volume counters in urr_volume_map.
   *
   * @param seid  PFCP session identifier
   * @param urr   Updated URR IE from PFCP Session Modification Request
   *
   * @see 3GPP TS 29.244 §7.5.4  — PFCP Session Modification Request
   */
  void Update(uint64_t seid, const std::shared_ptr<pfcp::pfcp_urr>& urr);

  /**
   * @brief Remove a single URR from all maps
   *
   * Removes both the config entry and the volume counter entry.
   * Called when a URR is explicitly removed via Session Modification.
   *
   * @param seid    PFCP session identifier
   * @param urr_id  URR identifier to remove
   *
   * @see 3GPP TS 29.244 §7.5.4  — PFCP Session Modification Request
   */
  void Remove(uint64_t seid, uint32_t urr_id);

  /**
   * @brief Tear down all URRs for a session on deletion
   *
   * Removes all config and volume entries for the session.
   * Does NOT send usage reports — caller (SessionManager) is responsible
   * for collecting final usage before calling TearDown().
   *
   * @param seid  PFCP session identifier
   * @param urrs  URRs to remove
   *
   * @see 3GPP TS 29.244 §7.5.6  — PFCP Session Deletion Request
   */
  void TearDown(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_urr>>& urrs);

  // ==========================================================================
  // BPF map population helpers (also called by SessionProgramManager)
  // ==========================================================================

  /**
   * @brief Populate urr_config_map for a single URR
   *
   * Translates the PFCP URR IE into a `pfcp_urr` BPF struct and writes
   * it into the map.
   *
   * @param seid  PFCP session identifier
   * @param urr   URR IE to convert and write
   * @param flags BPF_ANY (create or update) / BPF_NOEXIST / BPF_EXIST
   *
   * @see struct pfcp_urr in pfcp_urr.h
   */
  void PopulateUrrConfigMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_urr>& urr,
      uint64_t flags = BPF_ANY);

  /**
   * @brief Initialise urr_volume_map entry with BPF_NOEXIST
   *
   * Creates a zero-initialised counter entry only if it does not already
   * exist, preserving any in-flight accounting across session updates.
   *
   * @param seid    PFCP session identifier
   * @param urr_id  URR identifier
   */
  void InitUrrVolumeMap(uint64_t seid, uint32_t urr_id);

  /**
   * @brief Read current volume counters for a URR
   *
   * Used by SessionManager to collect usage for reporting.
   *
   * @param seid    PFCP session identifier
   * @param urr_id  URR identifier
   * @param[out] volume  Output volume counter struct
   * @return true  if entry found and populated
   * @return false if entry not found
   */
  bool ReadVolumeCounters(
      uint64_t seid, uint32_t urr_id, urr_volume_t& volume) const;

  // ==========================================================================
  // Map access
  // ==========================================================================

  /** @return Shared pointer to urr_config_map */
  std::shared_ptr<BPFMap> GetUrrConfigMap() const { return urr_config_map_; }

  /** @return Shared pointer to urr_volume_map */
  std::shared_ptr<BPFMap> GetUrrVolumeMap() const { return urr_volume_map_; }

 private:
  /**
   * @brief Build a urr_map_key from SEID and URR_ID
   * @param seid    PFCP session identifier
   * @param urr_id  URR identifier
   * @return        Populated key struct (pad zeroed)
   */
  static urr_map_key MakeKey(uint64_t seid, uint32_t urr_id);

  /**
   * @brief Translate PFCP URR IE into BPF pfcp_urr struct
   * @param pfcp_ie  Source PFCP URR IE
   * @param[out] bpf_urr  Output BPF struct
   */
  static void ConvertUrr(
      const pfcp::pfcp_urr& pfcp_ie, struct pfcp_urr& bpf_urr);

  std::shared_ptr<BPFMap> urr_config_map_;  ///< URR configuration map
  std::shared_ptr<BPFMap> urr_volume_map_;  ///< URR volume counter map
};

#endif  // URR_XDP_USER_H_
