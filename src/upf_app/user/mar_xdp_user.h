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
 * Changes:     V17.10.0 audit — fixed all §-refs in @see, Steering Modes
 *              comment, and struct field comment:
 *                - Section 8.2.7 — Create MAR IE: §8.2.7 = Gate Status in
 *                  V17.10.0; Create MAR grouped IE is at §7.5.2.8.
 *                - Section 8.2.74 — MAR ID: §8.2.74 = FAR ID in V17.10.0;
 *                  MAR ID is at §8.2.123.
 *                - Section 8.2.75 — Steering Mode: §8.2.75 = QER ID in
 *                  V17.10.0; Steering Mode is at §8.2.125.
 *                - Section 8.2.76 — Access Forwarding Action Information:
 *                  §8.2.76 = Activate Predefined Rules in V17.10.0; AFAI
 *                  Weight = §8.2.126, AFAI Priority = §8.2.127.
 *                - Steering Modes comment Section 8.2.124: §8.2.124 =
 *                  Steering Functionality; Steering Mode value encoding is
 *                  §8.2.125 — corrected label.
 *                - mar_map_key field comment (Section 8.2.74) → §8.2.123.
 *                - @see Section 7.2.2 / 7.2.4: neither exists in TS 29.244
 *                  V17.10.0; fixed to §7.5.2 (Establishment) / §7.5.4
 *                  (Modification) — same fix applied across all user/ files.
 *              Boy Scout: added changelog with clang-format guards; updated
 *              @author / @date.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/**
 * @file mar_xdp_user.h
 * @brief User-space manager for MAR (Multi-Access Rule) BPF maps
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * MARProgram manages the BPF maps that back the XDP tail-call program
 * `mar_apply` (PROG_MAR slot, index 6 in feature_dispatch_map).
 *
 * MAR implements ATSSS (Access Traffic Steering, Switching and Splitting)
 * which is the 5G mechanism for distributing traffic across 3GPP (N3)
 * and non-3GPP (N9/WLAN) accesses simultaneously.
 *
 * BPF Maps managed
 * ----------------
 *   mar_rules_map  — MAR configuration per (SEID, MAR_ID).
 *                    Written by control plane; read by mar_apply.c.
 *                    Stores pfcp_mar: steering mode + access FAR IDs.
 *
 * Steering Modes (3GPP TS 29.244 §8.2.125 Steering Mode / §8.2.124 Steering
 * Functionality)
 * ------------------------------------------
 *   STEER_ACTIVE_STANDBY : traffic to active access, failover to standby
 *   STEER_SMALLEST_DELAY : traffic to access with smaller RTT
 *   STEER_LOAD_BALANCE   : traffic split across both accesses
 *   STEER_PRIORITY_BASED : traffic to highest-priority access
 *
 * Map key
 * -------
 *   struct mar_map_key { uint64_t seid; uint32_t mar_id; uint32_t _pad; }
 *
 * @see 3GPP TS 29.244 §7.5.2.8  — Create MAR grouped IE
 * @see 3GPP TS 29.244 §8.2.123  — MAR ID
 * @see 3GPP TS 29.244 §8.2.125  — Steering Mode
 * @see 3GPP TS 29.244 §8.2.126  — Weight (AFAI)
 * @see 3GPP TS 29.244 §8.2.127  — Priority (AFAI)
 * @see 3GPP TS 23.501 Section 5.32   — ATSSS
 * @see kernel/xdp/mar_apply.c        — BPF tail-call program
 * @note Follows Google C++ Style Guide
 */

#ifndef MAR_XDP_USER_H_
#define MAR_XDP_USER_H_

#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <wrappers/BPFMap.hpp>
#include <pfcp_mar.h>        // struct pfcp_mar (shared kernel/user struct)
#include <pfcp_session.hpp>  // pfcp::pfcp_mar (PFCP IE wrapper)

class BPFMap;

// ==========================================================================
// Map key type
// ==========================================================================

/**
 * @struct mar_map_key
 * @brief Compound BPF map key for mar_rules_map
 *
 * Must match the key definition in mar_apply.c.
 */
struct mar_map_key {
  uint64_t seid;    ///< PFCP Session Endpoint Identifier
  uint32_t mar_id;  ///< MAR identifier (§8.2.123)
  uint32_t _pad;    ///< Alignment pad (must be zero)
} __attribute__((packed));

// ==========================================================================
// MARProgram
// ==========================================================================

/**
 * @class MARProgram
 * @brief User-space manager for MAR BPF maps in the XDP pipeline
 *
 * Responsibilities:
 *   - Translate PFCP MAR IEs into `pfcp_mar` BPF structs
 *   - Write steering configuration into mar_rules_map (BPF_ANY)
 *   - Remove entries on MAR deletion or session termination
 *
 * The BPF data plane uses steer_mode, active_access / standby_access,
 * n3_far_id and n9_far_id to implement ATSSS packet steering with no
 * control-plane involvement in the fast path.
 *
 * Thread Safety: Not thread-safe.  External locking required.
 *
 * @see mar_apply.c — corresponding BPF program
 * @note Follows Google C++ Style Guide
 */
class MARProgram {
 public:
  /**
   * @brief Constructor — receives shared BPFMap reference
   *
   * @param mar_rules_map  BPF map storing pfcp_mar config per (SEID, MAR_ID)
   *
   * @throws std::invalid_argument if map pointer is null
   */
  explicit MARProgram(std::shared_ptr<BPFMap> mar_rules_map);

  ~MARProgram() = default;

  // ==========================================================================
  // Session lifecycle
  // ==========================================================================

  /**
   * @brief Configure all MARs for a new session
   *
   * Populates mar_rules_map for each MAR in the list.
   *
   * @param seid  PFCP session identifier
   * @param mars  MAR IEs from PFCP Session Establishment Request
   *
   * @see 3GPP TS 29.244 §7.5.2  — PFCP Session Establishment Request
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_mar>>& mars);

  /**
   * @brief Update a single MAR for an existing session
   *
   * @param seid  PFCP session identifier
   * @param mar   Updated MAR IE from PFCP Session Modification Request
   *
   * @see 3GPP TS 29.244 §7.5.4  — PFCP Session Modification Request
   */
  void Update(uint64_t seid, const std::shared_ptr<pfcp::pfcp_mar>& mar);

  /**
   * @brief Remove a single MAR from mar_rules_map
   *
   * @param seid    PFCP session identifier
   * @param mar_id  MAR identifier to remove
   */
  void Remove(uint64_t seid, uint32_t mar_id);

  /**
   * @brief Tear down all MARs for a session on deletion
   *
   * @param seid  PFCP session identifier
   * @param mars  MARs to remove
   */
  void TearDown(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_mar>>& mars);

  // ==========================================================================
  // BPF map population helpers
  // ==========================================================================

  /**
   * @brief Populate mar_rules_map for a single MAR
   *
   * Translates the PFCP MAR IE (steering mode + AFAI 3GPP / Non-3GPP)
   * into a pfcp_mar struct and writes it into the map.
   *
   * @param seid   PFCP session identifier
   * @param mar    MAR IE to convert and write
   * @param flags  BPF_ANY / BPF_NOEXIST / BPF_EXIST
   *
   * @see struct pfcp_mar in pfcp_mar.h
   */
  void PopulateMarRulesMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_mar>& mar,
      uint64_t flags = BPF_ANY);

  // ==========================================================================
  // Map access
  // ==========================================================================

  /** @return Shared pointer to mar_rules_map */
  std::shared_ptr<BPFMap> GetMarRulesMap() const { return mar_rules_map_; }

 private:
  static mar_map_key MakeKey(uint64_t seid, uint32_t mar_id);
  static void ConvertMar(const pfcp::pfcp_mar& ie, struct pfcp_mar& bpf_mar);

  std::shared_ptr<BPFMap> mar_rules_map_;  ///< MAR rules map
};

#endif  // MAR_XDP_USER_H_
