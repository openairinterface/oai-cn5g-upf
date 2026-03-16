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
 *                - Fixed §-refs: BAR ID §8.2.57 (was §8.2.49),
 *                  Suggested Buffering Packets Count §8.2.100 (was §8.2.50).
 *                - Added interface applicability columns (Sxa/Sxb/Sxc/N4)
 *                  to every field comment.
 *                - Renamed dl_buffering_suggested_packet_count →
 *                  downlink_data_notification_delay (it stores the DDN delay,
 *                  not a packet count — misleading name).
 *                - Added dl_buffering_duration (§8.2.29, N4 applicable).
 *                - Added dl_buffering_suggested_packet_count (§8.2.30, N4).
 *                - Noted Downlink Data Notification Delay is N4-applicable
 *                  in Update BAR only (not in Create BAR).
 *                - Added mt_edt_control_information member (§8.2.172, Sxa
 *                  only, Create BAR) — TODO for lib gap.
 *                - IE table updated with cross-references to all 4 tables.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/*! \file pfcp_bar.hpp
   \author  Franck MESSAOUDI
   \date 2026
   \email: franck.messaoudi@eurecom.fr

   Control-plane representation of a Buffering Action Rule (BAR).

   BAR is referenced from a FAR (via bar_id) when apply_action.buff=1.
   SessionProgramManager::ConvertBar() translates this to the BPF struct
   pfcp_bar (pfcp_bar.h) written into bar_config_map.

   IE layout per 3GPP TS 29.244 V17.10.0 Table 7.5.2.6-1 (Create BAR)
   and Table 7.5.4.11-1 (Update BAR). See line-comment table below.
*/
// clang-format off
// IE name                          P   Sxa Sxb Sxc N4  §-ref       Table(s)
// ---------------------------------------------------------------------------
// BAR ID                           M    X   -   -   X   §8.2.57    7.5.2.6-1, 7.5.4.11-1, 7.5.4.12-1, 7.5.9.2-1
// Downlink Data Notification Delay C    X   -   - (*1)  §8.2.28    7.5.2.6-1, 7.5.4.11-1, 7.5.9.2-1
// Suggested Buffering Packets Count C   -   X   X   X   §8.2.100   7.5.2.6-1, 7.5.4.11-1, 7.5.9.2-1
// DL Buffering Duration            C    X   -   -   X   §8.2.29    7.5.2.6-1, 7.5.4.11-1, 7.5.9.2-1
// DL Buffering Suggested Pkt Count O    X   -   -   X   §8.2.30    7.5.2.6-1, 7.5.4.11-1, 7.5.9.2-1
// MT-EDT Control Information       O    X   -   -   -   §8.2.172   7.5.2.6-1 only (EPC/Sxa, Create BAR only)
//
// (*1) Downlink Data Notification Delay N4 applicability:
//      - Create BAR  (Table 7.5.2.6-1) : Sxa only (N4 = -)
//      - Update BAR  (Table 7.5.4.11-1): Sxa + N4  (N4 = X)
//      - Update BAR  (Table 7.5.9.2-1) : Sxa + N4  (N4 = X)
// clang-format on
//
// PFCP library gaps (msg_pfcp.hpp — not yet updated to V17.10.0):
//   update_bar_within_pfcp_session_modification_request is missing:
//     - dl_buffering_duration
//     - dl_buffering_suggested_packet_count
//   Both IEs are present in update_bar_within_pfcp_session_report_response.
//   Until the lib is updated, these fields can only be populated from a
//   Session Report Response, not from a Session Modification Request.
//   See TODO markers in pfcp_bar.cpp::update().
//
// Field naming notes:
//   pfcp::downlink_data_notification_delay_t has field .delay (uint8_t, x50
//   ms).
//   pfcp::suggested_buffering_packets_count_t has field .packets_count_value.
//   pfcp::dl_buffering_duration_t — commented out in 3gpp_29_244.hpp; used
//     via update_bar_within_pfcp_session_report_response.
//   pfcp::dl_buffering_suggested_packet_count_t — same.
//   ConvertBar accesses kernel struct fields by name (.delay_value,
//   .packet_count), so pfcp_bar uses local value-holder structs that expose
//   those exact field names.

#ifndef FILE_PFCP_BAR_HPP_SEEN
#define FILE_PFCP_BAR_HPP_SEEN

#include <cstdint>

#include "msg_pfcp.hpp"

namespace pfcp {

// ---------------------------------------------------------------------------
// Local value-holder types — field names match kernel struct + ConvertBar
// ---------------------------------------------------------------------------

/** @brief Holds Downlink Data Notification Delay (§8.2.28).
 *  .delay_value: delay in multiples of 50 ms (maps from
 *  pfcp::downlink_data_notification_delay_t.delay).
 *  Applicable: Sxa + N4 (Update BAR only; not in Create BAR for N4).
 */
struct bar_dl_delay_t {
  uint8_t delay_value = 0;
};

/** @brief Holds Suggested Buffering Packets Count (§8.2.100).
 *  .packet_count: max packets (UL or DL) to buffer before new quota
 *  (maps from pfcp::suggested_buffering_packets_count_t.packets_count_value).
 *  Applicable: Sxb + Sxc + N4.
 */
struct bar_buffering_count_t {
  uint8_t packet_count = 0;
};

/** @brief Holds DL Buffering Duration (§8.2.29).
 *  .timer_value: encoded as a GPRS Timer IE value (octet, 3-bit unit + 5-bit
 *  count, see 3GPP TS 24.008 §10.5.7.4a).
 *  Applicable: Sxa + N4.
 *  NOTE: not yet forwarded to kernel pfcp_bar BPF map (struct pfcp_bar in
 *  pfcp_bar.h has no dl_buffering_duration field). Add when kernel is updated.
 */
struct bar_dl_buffering_duration_t {
  uint8_t timer_value = 0;  ///< GPRS Timer encoding
};

/** @brief Holds DL Buffering Suggested Packet Count (§8.2.30).
 *  .suggested_packet_count: max DL packets to buffer during extended
 *  buffering (maps from pfcp::dl_buffering_suggested_packet_count_t).
 *  Applicable: Sxa + N4.
 *  NOTE: not yet forwarded to kernel pfcp_bar BPF map (struct pfcp_bar in
 *  pfcp_bar.h has no dl_buffering_suggested_packet_count field).
 */
struct bar_dl_buffering_suggested_count_t {
  uint16_t suggested_packet_count = 0;
};

// ---------------------------------------------------------------------------

/** @brief Control-plane representation of a Buffering Action Rule (BAR).
 *
 *  Stores all IEs from 3GPP TS 29.244 V17.10.0 Tables 7.5.2.6-1 (Create BAR),
 *  7.5.4.11-1 (Update BAR / Session Modification Request) and 7.5.9.2-1
 *  (Update BAR / Session Report Response).
 *  Converted to kernel BPF struct by SessionProgramManager::ConvertBar().
 *
 *  At most one BAR may be created per PFCP session (§5.2.4.1).
 */
class pfcp_bar {
 public:
  // ---- Mandatory -----------------------------------------------------------

  /// BAR ID — §8.2.57 — Sxa + N4
  std::pair<bool, pfcp::bar_id_t> bar_id;

  // ---- N4-applicable Optional / Conditional --------------------------------

  /// Downlink Data Notification Delay — §8.2.28 — Sxa + N4 (Update BAR only)
  /// .second.delay_value: ×50 ms before sending DDN to CP function.
  /// N4 applicability: Create BAR = NO, Update BAR (ModReq/RptRsp) = YES.
  std::pair<bool, pfcp::bar_dl_delay_t> downlink_data_notification_delay;

  /// Suggested Buffering Packets Count — §8.2.100 — Sxb + Sxc + N4 (UDBC
  /// feature) .second.packet_count: max UL+DL packets buffered before new quota
  /// granted.
  std::pair<bool, pfcp::bar_buffering_count_t>
      suggested_buffering_packets_count;

  /// DL Buffering Duration — §8.2.29 — Sxa + N4
  /// Extended buffering duration without sending further DDN.
  /// GPRS Timer encoding (see 3GPP TS 24.008 §10.5.7.4a).
  /// TODO: not yet forwarded to kernel struct pfcp_bar — add when pfcp_bar.h
  /// gains a dl_buffering_duration field.
  std::pair<bool, pfcp::bar_dl_buffering_duration_t> dl_buffering_duration;

  /// DL Buffering Suggested Packet Count — §8.2.30 — Sxa + N4
  /// Max DL packets to buffer during extended buffering.
  /// TODO: not yet forwarded to kernel struct pfcp_bar — add when pfcp_bar.h
  /// gains a dl_buffering_suggested_packet_count field.
  std::pair<bool, pfcp::bar_dl_buffering_suggested_count_t>
      dl_buffering_suggested_packet_count;

  /// MT-EDT Control Information — §8.2.172 — Sxa only (Create BAR,
  /// Table 7.5.2.6-1) Raw octet 5 of the IE (Figure 8.2.172-1). Bit 1 = RDSI
  /// flag. Stored for EPC/Sxa completeness; not forwarded to N4/kernel path.
  /// TODO: lib gap — pfcp::create_bar likely does not carry this IE yet.
  ///       When msg_pfcp.hpp adds mt_edt_control_information_t, populate in
  ///       pfcp_bar(const pfcp::create_bar& c) constructor below.
  std::pair<bool, uint8_t> mt_edt_control_information;  ///< octet 5 of §8.2.172

  //------------------------------------------------------------------------------
  /** @brief Default constructor — all optional IEs absent. */
  pfcp_bar()
      : bar_id(),
        downlink_data_notification_delay(),
        suggested_buffering_packets_count(),
        dl_buffering_duration(),
        dl_buffering_suggested_packet_count(),
        mt_edt_control_information() {}

  //------------------------------------------------------------------------------
  /** @brief Construct from Create BAR IE (3GPP TS 29.244 V17.10.0
   * Table 7.5.2.6-1).
   *
   *  Downlink Data Notification Delay is Sxa-only in Create BAR — stored for
   *  EPC/Sxa compatibility but flagged with a note.
   *  DL Buffering Duration and DL Buffering Suggested Packet Count are present
   *  in Create BAR only when it appears inside a Session Modification Request
   *  (§7.5.4.17); msg_pfcp.hpp create_bar does not carry them yet.
   */
  explicit pfcp_bar(const pfcp::create_bar& c) : bar_id(c.bar_id) {
    // Suggested Buffering Packets Count — §8.2.100, N4 applicable
    if (c.suggested_buffering_packets_count.first) {
      suggested_buffering_packets_count.first = true;
      suggested_buffering_packets_count.second.packet_count =
          c.suggested_buffering_packets_count.second.packets_count_value;
    }
    // Downlink Data Notification Delay — §8.2.28, Sxa-only in Create BAR
    if (c.downlink_data_notification_delay.first) {
      downlink_data_notification_delay.first = true;
      downlink_data_notification_delay.second.delay_value =
          c.downlink_data_notification_delay.second.delay;
    }
    // DL Buffering Duration and DL Buffering Suggested Packet Count:
    // not present in pfcp::create_bar (lib gap) — initialised to absent.

    // TODO §8.2.172 — MT-EDT Control Information (O, Sxa only, Create BAR)
    // Lib gap: pfcp::create_bar does not yet carry mt_edt_control_information.
    // When added:
    //   if (c.mt_edt_control_information.first) {
    //     mt_edt_control_information.first  = true;
    //     mt_edt_control_information.second =
    //     c.mt_edt_control_information.second.rdsi;
    //   }
  }

  //------------------------------------------------------------------------------
  /** @brief Copy constructor. */
  pfcp_bar(const pfcp_bar& c)
      : bar_id(c.bar_id),
        downlink_data_notification_delay(c.downlink_data_notification_delay),
        suggested_buffering_packets_count(c.suggested_buffering_packets_count),
        dl_buffering_duration(c.dl_buffering_duration),
        dl_buffering_suggested_packet_count(
            c.dl_buffering_suggested_packet_count),
        mt_edt_control_information(c.mt_edt_control_information) {}

  // ---- Setters from raw PFCP types ----------------------------------------

  //------------------------------------------------------------------------------
  void set(const pfcp::bar_id_t& v) {
    bar_id.first  = true;
    bar_id.second = v;
  }

  //------------------------------------------------------------------------------
  /** @brief Set Downlink Data Notification Delay — §8.2.28.
   *  @note N4-applicable in Update BAR only. */
  void set(const pfcp::downlink_data_notification_delay_t& v) {
    downlink_data_notification_delay.first              = true;
    downlink_data_notification_delay.second.delay_value = v.delay;
  }

  //------------------------------------------------------------------------------
  /** @brief Set Suggested Buffering Packets Count — §8.2.100 (UDBC feature). */
  void set(const pfcp::suggested_buffering_packets_count_t& v) {
    suggested_buffering_packets_count.first = true;
    suggested_buffering_packets_count.second.packet_count =
        v.packets_count_value;
  }

  //------------------------------------------------------------------------------
  /** @brief Set DL Buffering Duration — §8.2.29, N4 applicable.
   *  @note dl_buffering_duration_t is commented out in 3gpp_29_244.hpp;
   *        available via update_bar_within_pfcp_session_report_response.
   */
  void set(const pfcp::dl_buffering_duration_t& v) {
    dl_buffering_duration.first              = true;
    dl_buffering_duration.second.timer_value = v.timer_value;
  }

  //------------------------------------------------------------------------------
  /** @brief Set DL Buffering Suggested Packet Count — §8.2.30, N4 applicable.
   *  @note dl_buffering_suggested_packet_count_t is commented out in
   *        3gpp_29_244.hpp; available via
   *        update_bar_within_pfcp_session_report_response.
   */
  void set(const pfcp::dl_buffering_suggested_packet_count_t& v) {
    dl_buffering_suggested_packet_count.first = true;
    dl_buffering_suggested_packet_count.second.suggested_packet_count =
        v.packet_count;
  }

  // ---- Getters (return raw PFCP types) ------------------------------------

  //------------------------------------------------------------------------------
  bool get(pfcp::bar_id_t& v) const {
    if (bar_id.first) {
      v = bar_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  /** @brief Get Downlink Data Notification Delay — §8.2.28. */
  bool get(pfcp::downlink_data_notification_delay_t& v) const {
    if (downlink_data_notification_delay.first) {
      v.delay = downlink_data_notification_delay.second.delay_value;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  /** @brief Get Suggested Buffering Packets Count — §8.2.100. */
  bool get(pfcp::suggested_buffering_packets_count_t& v) const {
    if (suggested_buffering_packets_count.first) {
      v.packets_count_value =
          suggested_buffering_packets_count.second.packet_count;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  /** @brief Get DL Buffering Duration — §8.2.29. */
  bool get(pfcp::dl_buffering_duration_t& v) const {
    if (dl_buffering_duration.first) {
      v.timer_value = dl_buffering_duration.second.timer_value;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  /** @brief Get DL Buffering Suggested Packet Count — §8.2.30. */
  bool get(pfcp::dl_buffering_suggested_packet_count_t& v) const {
    if (dl_buffering_suggested_packet_count.first) {
      v.packet_count =
          dl_buffering_suggested_packet_count.second.suggested_packet_count;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  /** @brief Apply Update BAR IE from PFCP Session Modification Request
   *         (3GPP TS 29.244 V17.10.0 Table 7.5.4.11-1).
   *
   *  Handles: BAR ID, Downlink Data Notification Delay (§8.2.28),
   *           Suggested Buffering Packets Count (§8.2.100).
   *  Missing from lib: DL Buffering Duration (§8.2.29) and DL Buffering
   *  Suggested Packet Count (§8.2.30) — update_bar_within_pfcp_session_
   *  modification_request does not carry them yet (lib gap, TODO).
   *
   *  @param u           Update BAR within PFCP Session Modification Request IE.
   *  @param cause_value Populated with CAUSE_VALUE_* on return.
   *  @return true on success.
   */
  bool update(
      const pfcp::update_bar_within_pfcp_session_modification_request& u,
      uint8_t& cause_value);

  //------------------------------------------------------------------------------
  /** @brief Apply Update BAR IE from PFCP Session Report Response
   *         (3GPP TS 29.244 V17.10.0 Table 7.5.9.2-1).
   *
   *  Handles: BAR ID, Downlink Data Notification Delay (§8.2.28),
   *           DL Buffering Duration (§8.2.29),
   *           DL Buffering Suggested Packet Count (§8.2.30),
   *           Suggested Buffering Packets Count (§8.2.100).
   *
   *  @param u           Update BAR within PFCP Session Report Response IE.
   *  @param cause_value Populated with CAUSE_VALUE_* on return.
   *  @return true on success.
   */
  bool update(
      const pfcp::update_bar_within_pfcp_session_report_response& u,
      uint8_t& cause_value);
};

}  // namespace pfcp

#endif  // FILE_PFCP_BAR_HPP_SEEN
