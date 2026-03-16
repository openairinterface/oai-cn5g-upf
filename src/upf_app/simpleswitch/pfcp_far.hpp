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
 * Changes:     Boy Scout cleanup — Doxygen, 3GPP §-refs on all fields,
 *              separator lines, field grouping (Mandatory / Optional).
 *              V17.10.0 harmonisation:
 *                - Version bump V17.6.0 → V17.10.0.
 *                - Corrected ALL §-refs (every one had shifted from V17.6.0):
 *                    Apply Action        §8.2.17 → §8.2.26
 *                    Forwarding Parameters §8.2.15 → grouped IE type=4,
 *                      Table 7.5.2.3-2
 *                    Duplicating Parameters §8.2.16 → grouped IE type=5,
 *                      Table 7.5.2.3-3
 *                    BAR ID              §8.2.49 → §8.2.57
 *                - Fixed apply_forwarding_rules() Doxygen: QFI §8.2.75
 *                  (QER ID) → §8.2.89 (QFI).
 *                - Added interface applicability (Sxa/Sxb/Sxc/N4/N4mb) to
 *                  all field comments and full IE table.
 *                - Added Table(s) cross-reference column to IE table,
 *                  consistent with pfcp_bar/urr/mar/pdr/qer.hpp.
 *                - Added TODO entries for IEs not in OAI lib:
 *                  Redundant Transmission Forwarding Parameters (grouped IE
 *                  type=270, N4 only), MBS Multicast Parameters (grouped IE
 *                  type=301, N4mb only), Add MBS Unicast Parameters (grouped
 *                  IE type=302, N4mb only), Remove MBS Unicast Parameters
 *                  (grouped IE type=303, N4mb only, Update FAR only).
 *                - Removed unused kernel headers <linux/ip.h> and
 *                  <linux/ipv6.h> (no kernel types referenced in this file).
 *                - Fixed update() declaration: parameter renamed update →
 *                  updated_far (shadowed method name — boy scout fix).
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/*! \file pfcp_far.hpp
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr

   Control-plane representation of a Forwarding Action Rule (FAR).

   IE layout per 3GPP TS 29.244 V17.10.0 Table 7.5.2.3-1 (Create FAR)
   and Table 7.5.4.3-1 (Update FAR). See line-comment table below.
*/
// clang-format off
// Information element                        P   Sxa Sxb Sxc  N4 N4mb  §-ref       Table(s)
// ------------------------------------------------------------------------------------------
// FAR ID                                     M    X   X   X    X    X   §8.2.74     7.5.2.3-1, 7.5.4.3-1
// Apply Action                               M/C  X   X   X    X    X   §8.2.26     7.5.2.3-1, 7.5.4.3-1
// Forwarding Parameters                      C    X   X   X    X    -   grouped=4   7.5.2.3-2, 7.5.4.3-2
// Duplicating Parameters                     C    X   X   -    -    -   grouped=5   7.5.2.3-3, 7.5.4.3-3
// BAR ID                                     O/C  X   -   -    X    -   §8.2.57     7.5.2.3-1, 7.5.4.3-1
// Redundant Transmission Forwarding Params   C    -   -   -    X    -   grouped=270 7.5.2.3-4, 7.5.4.3-1  [TODO — N4 only; not in lib]
// MBS Multicast Parameters                   C    -   -   -    -    X   grouped=301 7.5.2.3-1 only         [TODO — N4mb only; not in lib]
// Add MBS Unicast Parameters                 C    -   -   -    -    X   grouped=302 7.5.2.3-1, 7.5.4.3-1  [TODO — N4mb only; not in lib]
// Remove MBS Unicast Parameters              C    -   -   -    -    X   grouped=303 7.5.4.3-1 only         [TODO — N4mb only; Update FAR only; not in lib]
// clang-format on
//
// OAI PFCP library gaps (msg_pfcp.hpp):
//   Redundant Transmission Forwarding Parameters (grouped IE type=270,
//     Table 7.5.2.3-4): N4 only; not in lib.
//   MBS Multicast Parameters (grouped IE type=301, Table 7.5.2.3-1):
//     N4mb only; not in lib.
//   Add MBS Unicast Parameters (grouped IE type=302, Tables 7.5.2.3-1,
//     7.5.4.3-1): N4mb only; not in lib.
//   Remove MBS Unicast Parameters (grouped IE type=303, Table 7.5.4.3-1):
//     N4mb only, Update FAR only; not in lib.

#ifndef FILE_PFCP_FAR_HPP_SEEN
#define FILE_PFCP_FAR_HPP_SEEN

#include "msg_pfcp.hpp"
struct iphdr;

namespace pfcp {

/** @brief Control-plane representation of a Forwarding Action Rule (FAR).
 *
 *  Stores all IEs from 3GPP TS 29.244 V17.10.0 Table 7.5.2.3-1 (Create FAR)
 *  and Table 7.5.4.3-1 (Update FAR).  apply_forwarding_rules() executes the
 *  data-plane action on each matched packet.
 */
class pfcp_far {
 public:
  // ---- Mandatory -----------------------------------------------------------
  pfcp::far_id_t far_id;              ///< §8.2.74  — Sxa+Sxb+Sxc+N4+N4mb
  pfcp::apply_action_t apply_action;  ///< §8.2.26  — Sxa+Sxb+Sxc+N4+N4mb

  // ---- Conditional / Optional ----------------------------------------------
  std::pair<bool, pfcp::forwarding_parameters>
      forwarding_parameters;  ///< grouped IE type=4, Table 7.5.2.3-2 —
                              ///< Sxa+Sxb+Sxc+N4
  std::pair<bool, pfcp::duplicating_parameters>
      duplicating_parameters;  ///< grouped IE type=5, Table 7.5.2.3-3 — Sxa+Sxb
  std::pair<bool, pfcp::bar_id_t> bar_id;  ///< §8.2.57  — Sxa+N4

  // TODO grouped=270 — Redundant Transmission Forwarding Parameters
  //   (C, N4 only, Tables 7.5.2.3-4, 7.5.4.3-1). Not in lib.
  // TODO grouped=301 — MBS Multicast Parameters
  //   (C, N4mb only, Table 7.5.2.3-1). Not in lib.
  // TODO grouped=302 — Add MBS Unicast Parameters
  //   (C, N4mb only, Tables 7.5.2.3-1, 7.5.4.3-1). Not in lib.
  // TODO grouped=303 — Remove MBS Unicast Parameters
  //   (C, N4mb only, Table 7.5.4.3-1, Update FAR only). Not in lib.

  //------------------------------------------------------------------------------
  /** @brief Default constructor — all optional IEs absent. */
  pfcp_far()
      : far_id(),
        apply_action(),
        forwarding_parameters(),
        duplicating_parameters(),
        bar_id() {}

  //------------------------------------------------------------------------------
  /** @brief Construct from Create FAR IE (3GPP TS 29.244 V17.10.0
   *  Table 7.5.2.3-1).
   */
  explicit pfcp_far(const pfcp::create_far& c)
      : forwarding_parameters(c.forwarding_parameters),
        duplicating_parameters(c.duplicating_parameters),
        bar_id(c.bar_id) {
    far_id       = c.far_id.second;
    apply_action = c.apply_action.second;
  }

  //------------------------------------------------------------------------------
  /** @brief Copy constructor. */
  pfcp_far(const pfcp_far& c)
      : far_id(c.far_id),
        apply_action(c.apply_action),
        forwarding_parameters(c.forwarding_parameters),
        duplicating_parameters(c.duplicating_parameters),
        bar_id(c.bar_id) {}

  // ---- Setters -------------------------------------------------------------

  //------------------------------------------------------------------------------
  void set(const pfcp::far_id_t& v) { far_id = v; }

  //------------------------------------------------------------------------------
  void set(const pfcp::apply_action_t& v) { apply_action = v; }

  //------------------------------------------------------------------------------
  void set(const pfcp::forwarding_parameters& v) {
    forwarding_parameters.first  = true;
    forwarding_parameters.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::duplicating_parameters& v) {
    duplicating_parameters.first  = true;
    duplicating_parameters.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::bar_id_t& v) {
    bar_id.first  = true;
    bar_id.second = v;
  }

  // ---- Getters -------------------------------------------------------------

  //------------------------------------------------------------------------------
  bool get(pfcp::far_id_t& v) const {
    v = far_id;
    return true;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::apply_action_t& v) const {
    v = apply_action;
    return true;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::forwarding_parameters& v) const {
    if (forwarding_parameters.first) {
      v = forwarding_parameters.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::duplicating_parameters& v) const {
    if (duplicating_parameters.first) {
      v = duplicating_parameters.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::bar_id_t& v) const {
    if (bar_id.first) {
      v = bar_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  /** @brief Apply Update FAR IE fields (3GPP TS 29.244 V17.10.0
   *  Table 7.5.4.3-1).
   *  @param updated_far Update FAR message IE.
   *  @param cause_value Populated with CAUSE_VALUE_* on return.
   *  @return true on success.
   */
  bool update(const pfcp::update_far& updated_far, uint8_t& cause_value);

  //------------------------------------------------------------------------------
  /** @brief Execute the forwarding action on a matched packet.
   *
   *  Handles FORW (encapsulate + send), DROP (silently discard), BUFF
   *  (set buff flag for caller), and NOCP (set nocp flag for caller).
   *  Duplication (DUPL) is not yet implemented.
   *
   *  @param iph        IPv4 header pointer (points into recv buffer).
   *  @param num_bytes  Payload length in bytes.
   *  @param nocp       Set to true if apply_action.nocp is set.
   *  @param buff       Set to true if apply_action.buff is set.
   *  @param qfi        QoS Flow Identifier for GTP-U extension header
   * (§8.2.75).
   */
  void apply_forwarding_rules(
      struct iphdr* const iph, const std::size_t num_bytes, bool& nocp,
      bool& buff, uint8_t qfi);
};
}  // namespace pfcp

#endif  // FILE_PFCP_FAR_HPP_SEEN
