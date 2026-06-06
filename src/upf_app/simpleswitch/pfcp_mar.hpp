/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

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

// ===========================================================================
// PFCP wire-IE shims for MAR (NOT YET IN common-src/pfcp/msg_pfcp.hpp)
//
// Until the OAI lib gains these types, we declare them locally so that the
// upf_app session-handling code can compile against a consistent type
// surface. When common-src adds equivalent definitions:
//   1. Delete this section.
//   2. Re-enable the MAR iteration blocks in SessionManager.cpp /
//      pfcp_switch.cpp that are currently guarded by `#if 0`.
// The class shapes below match 3GPP TS 29.244 §7.5.2.8 (Create MAR),
// §7.5.4.16 (Update MAR), §7.5.4.15 (Remove MAR), and §8.2.129/130 for
// Access Forwarding Action Information.
// ===========================================================================

/** @brief Access Forwarding Action Information IE (§8.2.129 / §8.2.130).
 *
 *  Wire form — distinct from mar_access_forwarding_action_t (internal).
 *  pfcp_session.cpp converts this to the internal form via field copies.
 */
class access_forwarding_action_information {
 public:
  std::pair<bool, pfcp::far_id_t> far_id;      ///< M — §8.2.74
  std::pair<bool, pfcp::urr_id_t> urr_id;      ///< C — §8.2.54
  std::pair<bool, pfcp::weight_t> weight;      ///< C — §8.2.126
  std::pair<bool, pfcp::priority_t> priority;  ///< C — §8.2.127

  access_forwarding_action_information() = default;

  bool get(pfcp::far_id_t& v) const {
    if (far_id.first) {
      v = far_id.second;
      return true;
    }
    return false;
  }

  bool get(pfcp::urr_id_t& v) const {
    if (urr_id.first) {
      v = urr_id.second;
      return true;
    }
    return false;
  }
};

/** @brief Create MAR IE (3GPP TS 29.244 §7.5.2.8, Table 7.5.2.8-1). */
class create_mar {
 public:
  std::pair<bool, pfcp::mar_id_t> mar_id;  ///< M — §8.2.123
  std::pair<bool, pfcp::steering_functionality_t>
      steering_functionality;  ///< M — §8.2.124
  std::pair<bool, pfcp::steering_mode_t> steering_mode;  ///< M — §8.2.125
  std::pair<bool, pfcp::access_forwarding_action_information>
      access_forwarding_action_information_1;  ///< C — §8.2.129
  std::pair<bool, pfcp::access_forwarding_action_information>
      access_forwarding_action_information_2;  ///< C — §8.2.130

  create_mar() = default;

  bool get(pfcp::mar_id_t& v) const {
    if (mar_id.first) {
      v = mar_id.second;
      return true;
    }
    return false;
  }
};

/** @brief Update MAR IE (3GPP TS 29.244 §7.5.4.16, Table 7.5.4.16-1). */
class update_mar {
 public:
  std::pair<bool, pfcp::mar_id_t> mar_id;  ///< M — §8.2.123
  std::pair<bool, pfcp::steering_functionality_t>
      steering_functionality;  ///< C — §8.2.124
  std::pair<bool, pfcp::steering_mode_t> steering_mode;  ///< C — §8.2.125
  std::pair<bool, pfcp::access_forwarding_action_information>
      access_forwarding_action_information_1;  ///< C — §8.2.129
  std::pair<bool, pfcp::access_forwarding_action_information>
      access_forwarding_action_information_2;  ///< C — §8.2.130

  update_mar() = default;

  bool get(pfcp::mar_id_t& v) const {
    if (mar_id.first) {
      v = mar_id.second;
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

  bool get_access_forwarding_action_information_1(
      pfcp::access_forwarding_action_information& v) const {
    if (access_forwarding_action_information_1.first) {
      v = access_forwarding_action_information_1.second;
      return true;
    }
    return false;
  }

  bool get_access_forwarding_action_information_2(
      pfcp::access_forwarding_action_information& v) const {
    if (access_forwarding_action_information_2.first) {
      v = access_forwarding_action_information_2.second;
      return true;
    }
    return false;
  }
};

/** @brief Remove MAR IE (3GPP TS 29.244 §7.5.4.15, Table 7.5.4.15-1). */
class remove_mar {
 public:
  std::pair<bool, pfcp::mar_id_t> mar_id;  ///< M — §8.2.123

  remove_mar() = default;

  bool get(pfcp::mar_id_t& v) const {
    if (mar_id.first) {
      v = mar_id.second;
      return true;
    }
    return false;
  }
};

}  // namespace pfcp

#endif  // FILE_PFCP_MAR_HPP_SEEN
