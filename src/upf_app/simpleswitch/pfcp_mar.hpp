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
 * Changes:     Boy Scout cleanup — Doxygen, 3GPP §-refs.
 *              V17.10.0 harmonisation:
 *                - Fixed table ref in file doc: Table 7.5.2.9-1 (Create SRR)
 *                  → Table 7.5.2.8-1 (Create MAR).
 *                - Fixed §-refs for AFAI: §8.2.75 (QER ID) and §8.2.76
 *                  (OCI Flags) were wrong; correct refs are IE type 166
 *                  Table 7.5.2.8-2 and IE type 167 Table 7.5.2.8-3.
 *                - Added interface applicability (N4-only) to all field
 *                  comments.
 *                - Added RAT Type (O, N4) to mar_access_forwarding_action_t
 *                  per Table 7.5.2.8-2 (§8.2.186, IE type 275).
 *                - Added Thresholds field (C, N4, §8.2.196, IE type 288).
 *                - Added Steering Mode Indicator field (C, N4, §8.2.197,
 *                  IE type 289).
 *                - Reformatted IE table: unified column layout with
 *                  Sxa/Sxb/Sxc/N4 and Table(s) cross-reference column,
 *                  consistent with pfcp_bar.hpp and pfcp_urr.hpp.
 *                - Update-only IEs (7.5.4.16-1) now explicitly annotated.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/*! \file pfcp_mar.hpp
   \author  Franck MESSAOUDI
   \date 2026
   \email: franck.messaoudi@eurecom.fr

   Control-plane representation of a Multi-Access Rule (MAR).

   MAR implements ATSSS (3GPP TS 23.501 §5.32). A PDR references a MAR
   via mar_id for per-session multi-access steering between 3GPP (N3)
   and non-3GPP (N9/WLAN) access paths.

   SessionProgramManager::ConvertMar() translates this to the BPF struct
   pfcp_mar (pfcp_mar.h) written into mar_rules_map.

   IE layout per 3GPP TS 29.244 V17.10.0 Table 7.5.2.8-1 (Create MAR).
   All IEs are N4-only. See line-comment tables below.
*/
// clang-format off
// IE name                              P  Sxa Sxb Sxc  N4  §-ref / IE-type ref    Table(s)
// ------------------------------------------------------------------------------------------
// --- Create MAR (Table 7.5.2.8-1) + Update MAR (Table 7.5.4.16-1) — all N4-only ---
// MAR ID                               M   -   -   -    X   §8.2.123 (IE 170)     7.5.2.8-1, 7.5.4.16-1, 7.5.4.15-1
// Steering Functionality               M   -   -   -    X   §8.2.124 (IE 171)     7.5.2.8-1, 7.5.4.16-1
// Steering Mode                        M   -   -   -    X   §8.2.125 (IE 172)     7.5.2.8-1, 7.5.4.16-1
// 3GPP Access Forwarding Action Info   C   -   -   -    X   IE type 166            7.5.2.8-1, 7.5.4.16-1
// Non-3GPP Access Forwarding Action    C   -   -   -    X   IE type 167            7.5.2.8-1, 7.5.4.16-1
// Threshold Values                     C   -   -   -    X   §8.2.196  (IE 288)    7.5.2.8-1, 7.5.4.16-1
// Steering Mode Indicator              C   -   -   -    X   §8.2.197  (IE 289)    7.5.2.8-1, 7.5.4.16-1
// Update 3GPP Access Fwd Action        C   -   -   -    X   IE type 175            7.5.4.16-1 only
// Update Non-3GPP Access Fwd Action    C   -   -   -    X   IE type 176            7.5.4.16-1 only
//
// --- Access Forwarding Action sub-IEs (Tables 7.5.2.8-2/3, 7.5.4.16-2/3) — N4-only ---
// FAR ID                               M   -   -   -    X   §8.2.74               7.5.2.8-2, 7.5.2.8-3, 7.5.4.16-2, 7.5.4.16-3
// Weight                               C   -   -   -    X   §8.2.126 (Load Bal.)  7.5.2.8-2, 7.5.2.8-3, 7.5.4.16-2, 7.5.4.16-3
// Priority                             C   -   -   -    X   §8.2.127 (Act-Stby)   7.5.2.8-2, 7.5.2.8-3, 7.5.4.16-2, 7.5.4.16-3
// URR ID                               C   -   -   -    X   §8.2.54               7.5.2.8-2, 7.5.2.8-3, 7.5.4.16-2, 7.5.4.16-3
// RAT Type                             O   -   -   -    X   §8.2.186 (IE 275)     7.5.2.8-2, 7.5.2.8-3, 7.5.4.16-2, 7.5.4.16-3
// clang-format on
//
// OAI PFCP library status (msg_pfcp.hpp):
//   pfcp::mar_id_t               — EXISTS (§8.2.123)
//   pfcp::steering_functionality_t — EXISTS (§8.2.124)
//   pfcp::steering_mode_t         — EXISTS (§8.2.125)
//   pfcp::weight_t                — EXISTS (§8.2.126)
//   pfcp::priority_t              — EXISTS (§8.2.127)
//   pfcp::create_mar / update_mar — NOT implemented in msg_pfcp.hpp
//   access_forwarding_action_information — NOT implemented in msg_pfcp.hpp
//   pfcp::thresholds_t            — NOT implemented (§8.2.196, IE type 288)
//   pfcp::steering_mode_indicator_t — NOT implemented (§8.2.197, IE type 289)
//
// The access forwarding and new V17.10 structs are defined locally here.
// When create_mar / update_mar are added to msg_pfcp.hpp, replace the
// local structs with the library types and add a create_mar constructor.

#ifndef FILE_PFCP_MAR_HPP_SEEN
#define FILE_PFCP_MAR_HPP_SEEN

#include <cstdint>
#include <vector>

#include "msg_pfcp.hpp"  // pfcp::mar_id_t, steering_mode_t,
                         // steering_functionality_t, far_id_t,
                         // weight_t, priority_t, urr_id_t

namespace pfcp {

// ---------------------------------------------------------------------------
// Local value-holder types for IEs not yet in msg_pfcp.hpp
// ---------------------------------------------------------------------------

/** @brief Holds Thresholds IE (§8.2.196, IE type 288).
 *  Conditional: present when Steering Mode is Load-Balancing with fixed split
 *  percentages or Priority-based. Contains RTT and/or Packet Loss Rate.
 *  N4-only.
 *  TODO: replace with pfcp::thresholds_t when added to msg_pfcp.hpp.
 */
struct mar_thresholds_t {
  bool rtt_present              = false;
  uint32_t rtt_ms               = 0;  ///< Round-trip time threshold (ms)
  bool packet_loss_rate_present = false;
  uint8_t packet_loss_rate      = 0;  ///< Packet loss rate threshold (%)
};

/** @brief Holds Steering Mode Indicator IE (§8.2.197, IE type 289).
 *  Conditional: present if ALBI or UEAI flag is set to 1.
 *  N4-only.
 *  TODO: replace with pfcp::steering_mode_indicator_t when added to
 *  msg_pfcp.hpp.
 */
struct mar_steering_mode_indicator_t {
  bool albi = false;  ///< Autonomous Load Balancing Indicator
  bool ueai = false;  ///< UE Assistance Indicator
};

// ---------------------------------------------------------------------------
// Access Forwarding Action Information
// Not yet in msg_pfcp.hpp — local minimal definition.
// ---------------------------------------------------------------------------

/** @brief Local representation of Access Forwarding Action Information.
 *
 *  Used for both 3GPP access (IE type 166, Table 7.5.2.8-2) and non-3GPP
 *  access (IE type 167, Table 7.5.2.8-3) paths.
 *  All IEs are N4-only.
 *  Not yet in msg_pfcp.hpp — replace with library type when create_mar /
 *  update_mar are added.
 */
struct mar_access_forwarding_action_t {
  pfcp::far_id_t far_id;  ///< Mandatory — FAR for this access path §8.2.74
  pfcp::weight_t weight;  ///< Conditional — Load Balancing mode §8.2.126
  pfcp::priority_t
      priority;           ///< Conditional — Active-Standby/Priority §8.2.127
  pfcp::urr_id_t urr_id;  ///< Conditional — per-access usage reporting §8.2.54
  uint8_t rat_type;       ///< Optional — RAT Type §8.2.186 (IE type 275)

  bool weight_present   = false;
  bool priority_present = false;
  bool urr_id_present   = false;
  bool rat_type_present =
      false;  ///< V17.10.0: RAT Type added to AFAI sub-table
};

// ---------------------------------------------------------------------------

/** @brief Control-plane representation of a Multi-Access Rule (MAR).
 *
 *  Stores all IEs from 3GPP TS 29.244 V17.10.0 Table 7.5.2.8-1 (Create MAR)
 *  and Table 7.5.4.16-1 (Update MAR within PFCP Session Modification Request).
 *  Converted to kernel BPF struct by SessionProgramManager::ConvertMar().
 *  Populated via set() / set_3gpp_access() / set_non3gpp_access() calls in
 *  SessionProgramManager (create_mar / update_mar not yet in OAI lib).
 *
 *  All IEs are N4-only (Sxa=-, Sxb=-, Sxc=-, N4=X, N4mb=-).
 */
class pfcp_mar {
 public:
  // ---- Mandatory — N4 -------------------------------------------------------

  std::pair<bool, pfcp::mar_id_t> mar_id;  ///< §8.2.123, IE type 170

  // ---- Mandatory per spec, populated from Session-Establishment — N4 --------

  std::pair<bool, pfcp::steering_functionality_t>
      steering_functionality;  ///< §8.2.124, IE type 171

  std::pair<bool, pfcp::steering_mode_t>
      steering_mode;  ///< §8.2.125, IE type 172

  // ---- Conditional — N4 -----------------------------------------------------

  /// 3GPP access path forwarding action.
  /// IE type 166, Table 7.5.2.8-2.
  /// .second.far_id.far_id used by ConvertMar().
  std::pair<bool, pfcp::mar_access_forwarding_action_t>
      access_forwarding_action_info_1;

  /// Non-3GPP access path forwarding action.
  /// IE type 167, Table 7.5.2.8-3.
  /// .second.far_id.far_id used by ConvertMar().
  std::pair<bool, pfcp::mar_access_forwarding_action_t>
      access_forwarding_action_info_2;

  /// Threshold Values (C, N4) — §8.2.196, IE type 288.
  /// Present when Steering Mode is Load-Balancing with fixed split or
  /// Priority-based. Contains RTT and/or Packet Loss Rate thresholds.
  /// NOTE: Threshold Values and Steering Mode Indicator shall not be
  /// present together (Table 7.5.2.8-1 NOTE 2).
  /// TODO: not yet forwarded to kernel struct pfcp_mar — add when
  /// pfcp_mar.h gains a thresholds field.
  std::pair<bool, pfcp::mar_thresholds_t> thresholds;

  /// Steering Mode Indicator (C, N4) — §8.2.197, IE type 289.
  /// Present if ALBI or UEAI flag is set. ALBI and UEAI cannot both be 1.
  /// NOTE: shall not be present together with Threshold Values.
  /// TODO: not yet forwarded to kernel struct pfcp_mar — add when
  /// pfcp_mar.h gains a steering_mode_indicator field.
  std::pair<bool, pfcp::mar_steering_mode_indicator_t> steering_mode_indicator;

  /** @brief Default constructor — all optional IEs absent. */
  pfcp_mar()
      : mar_id(),
        steering_functionality(),
        steering_mode(),
        access_forwarding_action_info_1(),
        access_forwarding_action_info_2(),
        thresholds(),
        steering_mode_indicator() {}

  /** @brief Copy constructor. */
  pfcp_mar(const pfcp_mar& c)
      : mar_id(c.mar_id),
        steering_functionality(c.steering_functionality),
        steering_mode(c.steering_mode),
        access_forwarding_action_info_1(c.access_forwarding_action_info_1),
        access_forwarding_action_info_2(c.access_forwarding_action_info_2),
        thresholds(c.thresholds),
        steering_mode_indicator(c.steering_mode_indicator) {}

  // ---- Setters --------------------------------------------------------------

  void set(const pfcp::mar_id_t& v) {
    mar_id.first  = true;
    mar_id.second = v;
  }

  void set(const pfcp::steering_functionality_t& v) {
    steering_functionality.first  = true;
    steering_functionality.second = v;
  }

  void set(const pfcp::steering_mode_t& v) {
    steering_mode.first  = true;
    steering_mode.second = v;
  }

  /** @brief Set 3GPP access path forwarding action (IE type 166,
   * Table 7.5.2.8-2). */
  void set_3gpp_access(const pfcp::mar_access_forwarding_action_t& v) {
    access_forwarding_action_info_1.first  = true;
    access_forwarding_action_info_1.second = v;
  }

  /** @brief Set non-3GPP access path forwarding action (IE type 167,
   * Table 7.5.2.8-3). */
  void set_non3gpp_access(const pfcp::mar_access_forwarding_action_t& v) {
    access_forwarding_action_info_2.first  = true;
    access_forwarding_action_info_2.second = v;
  }

  /** @brief Set Threshold Values — §8.2.196, IE type 288 (N4, V17.10.0). */
  void set(const pfcp::mar_thresholds_t& v) {
    thresholds.first  = true;
    thresholds.second = v;
  }

  /** @brief Set Steering Mode Indicator — §8.2.197, IE type 289 (N4, V17.10.0).
   */
  void set(const pfcp::mar_steering_mode_indicator_t& v) {
    steering_mode_indicator.first  = true;
    steering_mode_indicator.second = v;
  }

  // ---- Getters --------------------------------------------------------------

  bool get(pfcp::mar_id_t& v) const {
    if (mar_id.first) {
      v = mar_id.second;
      return true;
    }
    return false;
  }

  bool get(pfcp::steering_functionality_t& v) const {
    if (steering_functionality.first) {
      v = steering_functionality.second;
      return true;
    }
    return false;
  }

  bool get(pfcp::steering_mode_t& v) const {
    if (steering_mode.first) {
      v = steering_mode.second;
      return true;
    }
    return false;
  }

  /** @brief Get 3GPP access path forwarding action (IE type 166).
   *  @return true if present.
   */
  bool get_3gpp_access(pfcp::mar_access_forwarding_action_t& v) const {
    if (access_forwarding_action_info_1.first) {
      v = access_forwarding_action_info_1.second;
      return true;
    }
    return false;
  }

  /** @brief Get non-3GPP access path forwarding action (IE type 167).
   *  @return true if present.
   */
  bool get_non3gpp_access(pfcp::mar_access_forwarding_action_t& v) const {
    if (access_forwarding_action_info_2.first) {
      v = access_forwarding_action_info_2.second;
      return true;
    }
    return false;
  }

  /** @brief Get Threshold Values — §8.2.196 (N4, V17.10.0).
   *  @return true if present.
   */
  bool get(pfcp::mar_thresholds_t& v) const {
    if (thresholds.first) {
      v = thresholds.second;
      return true;
    }
    return false;
  }

  /** @brief Get Steering Mode Indicator — §8.2.197 (N4, V17.10.0).
   *  @return true if present.
   */
  bool get(pfcp::mar_steering_mode_indicator_t& v) const {
    if (steering_mode_indicator.first) {
      v = steering_mode_indicator.second;
      return true;
    }
    return false;
  }
};

}  // namespace pfcp

#endif  // FILE_PFCP_MAR_HPP_SEEN
