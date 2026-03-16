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
 * Changes:     V17.10.0 audit — fixed all three §-refs in @see block and
 *              struct field comment:
 *                - Section 8.2.6 — Create BAR IE: §8.2.6 = Application ID
 *                  in V17.10.0; Create BAR grouped IE is at §7.5.2.7.
 *                - Section 8.2.49 — BAR ID: §8.2.49 = Dropped DL Traffic
 *                  Threshold in V17.10.0; BAR ID is at §8.2.57.  Also fixed
 *                  in bar_map_key field comment.
 *                - Section 8.2.50 — Suggested Buffering Packets Count:
 *                  §8.2.50 = Volume Quota in V17.10.0; Suggested Buffering
 *                  Packets Count is at §8.2.100.
 *              Boy Scout: added changelog with clang-format guards; updated
 *              @author / @date.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/**
 * @file bar_xdp_user.h
 * @brief User-space manager for BAR (Buffering Action Rule) BPF maps
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * BARProgram manages the BPF maps that back the XDP tail-call program
 * `bar_apply` (PROG_BAR slot, index 5 in feature_dispatch_map).
 *
 * BAR is referenced indirectly: a FAR with apply_action.buff=1 carries a
 * BAR_ID that indexes into bar_config_map to control buffering behaviour.
 * This side path is terminal — after buffering, the packet is dropped from
 * the forwarding pipeline.
 *
 * BPF Maps managed
 * ----------------
 *   bar_config_map  — BAR configuration per (SEID, BAR_ID).
 *                     Written by control plane; read by bar_apply.c.
 *                     Stores pfcp_bar: DDN delay + buffer packet count hint.
 *
 *   bar_state_map   — Runtime buffering state per (SEID, BAR_ID).
 *                     Written atomically by data plane; read by control plane.
 *                     Stores: last DDN timestamp, buffered packet count,
 *                     notification-sent flag.
 *                     NEVER reset during modification — state preserved
 *                     across session updates to avoid spurious DDN retrigger.
 *
 * Map key
 * -------
 *   struct bar_map_key { uint64_t seid; uint32_t bar_id; uint32_t _pad; }
 *
 * DDN suppression logic
 * ---------------------
 *   dl_notification_delay_sec > 0: the data plane suppresses duplicate DDN
 *   notifications within the delay window (bar_state.last_ddn_ns).
 *   The control plane must NOT clear last_ddn_ns during modification —
 *   handled by BPF_NOEXIST state initialisation.
 *
 * @see 3GPP TS 29.244 §7.5.2.7  — Create BAR grouped IE
 * @see 3GPP TS 29.244 §8.2.57   — BAR ID
 * @see 3GPP TS 29.244 §8.2.100  — Suggested Buffering Packets Count
 * @see 3GPP TS 29.244 §8.2.28   — DL Data Notification Delay
 * @see kernel/xdp/bar_apply.c        — BPF tail-call program
 * @note Follows Google C++ Style Guide
 */

#ifndef BAR_XDP_USER_H_
#define BAR_XDP_USER_H_

#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <wrappers/BPFMap.hpp>
#include <pfcp_bar.h>        // struct pfcp_bar (shared kernel/user struct)
#include <pfcp_session.hpp>  // pfcp::pfcp_bar (PFCP IE wrapper)

class BPFMap;

// ==========================================================================
// Map key type
// ==========================================================================

/**
 * @struct bar_map_key
 * @brief Compound BPF map key for BAR config and state maps
 *
 * Must match the key definition in bar_apply.c.
 */
struct bar_map_key {
  uint64_t seid;    ///< PFCP Session Endpoint Identifier
  uint32_t bar_id;  ///< BAR identifier (§8.2.57)
  uint32_t _pad;    ///< Alignment pad (must be zero)
} __attribute__((packed));

// ==========================================================================
// Buffering state type (runtime, written by data plane)
// ==========================================================================

/**
 * @struct bar_state_t
 * @brief Runtime buffering state maintained atomically by the data plane
 *
 * Initialised with BPF_NOEXIST on session creation so that existing state
 * is preserved across session modifications.
 *
 * The control plane reads these fields to:
 *   - Decide whether to send a DL Data Notification (DDN)
 *   - Count how many DL packets have been buffered
 *
 * @see 3GPP TS 29.244 §8.2.28 — DL Data Notification Delay
 */
struct bar_state_t {
  uint64_t last_ddn_ns;         ///< bpf_ktime_get_ns() at last DDN send
  uint32_t buffered_pkt_count;  ///< DL packets buffered since last DDN
  uint8_t notification_sent;    ///< 1 if DDN already sent this window
  uint8_t _pad[3];
};

// ==========================================================================
// BARProgram
// ==========================================================================

/**
 * @class BARProgram
 * @brief User-space manager for BAR BPF maps in the XDP pipeline
 *
 * Responsibilities:
 *   - Translate PFCP BAR IEs into `pfcp_bar` BPF structs
 *   - Write configuration into bar_config_map (BPF_ANY)
 *   - Initialise buffering state in bar_state_map (BPF_NOEXIST)
 *   - Read runtime state for DDN control plane signalling
 *   - Remove entries on BAR deletion or session termination
 *
 * Thread Safety: Not thread-safe.  External locking required.
 *
 * @see bar_apply.c — corresponding BPF program
 * @note Follows Google C++ Style Guide
 */
class BARProgram {
 public:
  /**
   * @brief Constructor — receives shared BPFMap references
   *
   * @param bar_config_map  BPF map storing pfcp_bar config per (SEID, BAR_ID)
   * @param bar_state_map   BPF map storing runtime buffering state
   *
   * @throws std::invalid_argument if either map pointer is null
   */
  BARProgram(
      std::shared_ptr<BPFMap> bar_config_map,
      std::shared_ptr<BPFMap> bar_state_map);

  ~BARProgram() = default;

  // ==========================================================================
  // Session lifecycle
  // ==========================================================================

  /**
   * @brief Configure all BARs for a new session
   *
   * Populates bar_config_map and initialises bar_state_map (BPF_NOEXIST)
   * for each BAR in the list.
   *
   * @param seid  PFCP session identifier
   * @param bars  BAR IEs from PFCP Session Establishment Request
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars);

  /**
   * @brief Update a single BAR for an existing session
   *
   * Overwrites the config entry; bar_state_map is NOT touched so that DDN
   * suppression state and buffered packet count are preserved.
   *
   * @param seid  PFCP session identifier
   * @param bar   Updated BAR IE from PFCP Session Modification Request
   */
  void Update(uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar);

  /**
   * @brief Remove a single BAR from all maps
   *
   * @param seid    PFCP session identifier
   * @param bar_id  BAR identifier to remove
   */
  void Remove(uint64_t seid, uint32_t bar_id);

  /**
   * @brief Tear down all BARs for a session on deletion
   *
   * @param seid  PFCP session identifier
   * @param bars  BARs to remove
   */
  void TearDown(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars);

  // ==========================================================================
  // BPF map population helpers
  // ==========================================================================

  /**
   * @brief Populate bar_config_map for a single BAR
   *
   * @param seid   PFCP session identifier
   * @param bar    BAR IE to convert and write
   * @param flags  BPF_ANY / BPF_NOEXIST / BPF_EXIST
   */
  void PopulateBarConfigMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar,
      uint64_t flags = BPF_ANY);

  /**
   * @brief Initialise bar_state_map entry (BPF_NOEXIST — preserves state)
   *
   * @param seid    PFCP session identifier
   * @param bar_id  BAR identifier
   */
  void InitBarStateMap(uint64_t seid, uint32_t bar_id);

  /**
   * @brief Read current buffering state for a BAR
   *
   * Used by SessionManager for DDN signalling decisions.
   *
   * @param seid    PFCP session identifier
   * @param bar_id  BAR identifier
   * @param[out] state  Output state struct
   * @return true if entry found
   */
  bool ReadBarState(uint64_t seid, uint32_t bar_id, bar_state_t& state) const;

  // ==========================================================================
  // Map access
  // ==========================================================================

  /** @return Shared pointer to bar_config_map */
  std::shared_ptr<BPFMap> GetBarConfigMap() const { return bar_config_map_; }

  /** @return Shared pointer to bar_state_map */
  std::shared_ptr<BPFMap> GetBarStateMap() const { return bar_state_map_; }

 private:
  static bar_map_key MakeKey(uint64_t seid, uint32_t bar_id);
  static void ConvertBar(const pfcp::pfcp_bar& ie, struct pfcp_bar& bpf_bar);

  std::shared_ptr<BPFMap> bar_config_map_;  ///< BAR configuration map
  std::shared_ptr<BPFMap> bar_state_map_;   ///< BAR runtime state map
};

#endif  // BAR_XDP_USER_H_
