/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PFCP_QER_HPP_SEEN
#define FILE_PFCP_QER_HPP_SEEN

#include "msg_pfcp.hpp"

namespace pfcp {

/** @brief Control-plane representation of a QoS Enforcement Rule (QER).
 *
 *  Stores all IEs from 3GPP TS 29.244 V17.10.0 Table 7.5.2.5-1 (Create QER)
 *  and Table 7.5.4.5-1 (Update QER). SessionProgramManager::ConvertQer()
 *  translates this to the BPF struct written into qer_config_map.
 */
class pfcp_qer {
 public:
  // ---- Mandatory -----------------------------------------------------------
  std::pair<bool, pfcp::qer_id_t> qer_id;  ///< §8.2.75 — Sxb+Sxc+N4+N4mb
  std::pair<bool, pfcp::gate_status_t>
      gate_status;  ///< §8.2.7  — Sxb+Sxc+N4+N4mb

  // ---- Conditional / Optional ----------------------------------------------
  std::pair<bool, pfcp::qer_correlation_id_t>
      qer_correlation_id;                        ///< §8.2.10  — Sxb+N4
  std::pair<bool, pfcp::mbr_t> maximum_bitrate;  ///< §8.2.8   — Sxb+Sxc+N4+N4mb
  std::pair<bool, pfcp::gbr_t>
      guaranteed_bitrate;                    ///< §8.2.9   — Sxb+Sxc+N4+N4mb
  std::pair<bool, pfcp::qfi_t> qos_flow_id;  ///< §8.2.89  — N4+N4mb
  std::pair<bool, pfcp::rqi_t> reflective_qos;  ///< §8.2.88  — N4 only
  std::pair<bool, pfcp::paging_policy_indicator_t>
      paging_policy_indicator;  ///< §8.2.116 — N4 only
  std::pair<bool, pfcp::averaging_window_t>
      averaging_window;  ///< §8.2.115 — N4 only

  // TODO §8.2.174: QER Control Indications — absent from pfcp::create_qer in
  //   lib. Present in pfcp::update_qer; add to pfcp_qer and update() when lib
  //   is updated.
  // TODO §8.2.216: QER Indications — N4mb only; not in lib at all.

  //------------------------------------------------------------------------------
  /** @brief Default constructor — all optional IEs absent. */
  pfcp_qer()
      : qer_id(),
        gate_status(),
        qer_correlation_id(),
        maximum_bitrate(),
        guaranteed_bitrate(),
        qos_flow_id(),
        reflective_qos(),
        paging_policy_indicator(),
        averaging_window() {}

  //------------------------------------------------------------------------------
  /** @brief Construct from Create QER IE (3GPP TS 29.244 V17.10.0
   *  Table 7.5.2.5-1).
   */
  explicit pfcp_qer(const pfcp::create_qer& c)
      : qer_id(c.qer_id),
        gate_status(c.gate_status),
        qer_correlation_id(c.qer_correlation_id),
        maximum_bitrate(c.maximum_bitrate),
        guaranteed_bitrate(c.guaranteed_bitrate),
        qos_flow_id(c.qos_flow_identifier),
        reflective_qos(c.reflective_qos),
        paging_policy_indicator(c.paging_policy_indicator),
        averaging_window(c.averaging_window) {}

  //------------------------------------------------------------------------------
  /** @brief Copy constructor. */
  pfcp_qer(const pfcp_qer& c)
      : qer_id(c.qer_id),
        gate_status(c.gate_status),
        qer_correlation_id(c.qer_correlation_id),
        maximum_bitrate(c.maximum_bitrate),
        guaranteed_bitrate(c.guaranteed_bitrate),
        qos_flow_id(c.qos_flow_id),
        reflective_qos(c.reflective_qos),
        paging_policy_indicator(c.paging_policy_indicator),
        averaging_window(c.averaging_window) {}

  // ---- Setters -------------------------------------------------------------

  //------------------------------------------------------------------------------
  void set(const pfcp::qer_id_t& v) {
    qer_id.first  = true;
    qer_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::qer_correlation_id_t& v) {
    qer_correlation_id.first  = true;
    qer_correlation_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::gate_status_t& v) {
    gate_status.first  = true;
    gate_status.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::mbr_t& v) {
    maximum_bitrate.first  = true;
    maximum_bitrate.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::gbr_t& v) {
    guaranteed_bitrate.first  = true;
    guaranteed_bitrate.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::qfi_t& v) {
    qos_flow_id.first  = true;
    qos_flow_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::rqi_t& v) {
    reflective_qos.first  = true;
    reflective_qos.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::paging_policy_indicator_t& v) {
    paging_policy_indicator.first  = true;
    paging_policy_indicator.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::averaging_window_t& v) {
    averaging_window.first  = true;
    averaging_window.second = v;
  }

  // ---- Getters -------------------------------------------------------------

  //------------------------------------------------------------------------------
  bool get(pfcp::qer_id_t& v) const {
    if (qer_id.first) {
      v = qer_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::gate_status_t& v) const {
    if (gate_status.first) {
      v = gate_status.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::qer_correlation_id_t& v) const {
    if (qer_correlation_id.first) {
      v = qer_correlation_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::mbr_t& v) const {
    if (maximum_bitrate.first) {
      v = maximum_bitrate.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::gbr_t& v) const {
    if (guaranteed_bitrate.first) {
      v = guaranteed_bitrate.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::qfi_t& v) const {
    if (qos_flow_id.first) {
      v = qos_flow_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::rqi_t& v) const {
    if (reflective_qos.first) {
      v = reflective_qos.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::paging_policy_indicator_t& v) const {
    if (paging_policy_indicator.first) {
      v = paging_policy_indicator.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::averaging_window_t& v) const {
    if (averaging_window.first) {
      v = averaging_window.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  /** @brief Apply Update QER IE fields (3GPP TS 29.244 V17.10.0
   *  Table 7.5.4.5-1).
   *  @param updated_qer Update QER message IE.
   *  @param cause_value Populated with CAUSE_VALUE_* on return.
   *  @return true on success.
   */
  bool update(const pfcp::update_qer& updated_qer, uint8_t& cause_value);
};
}  // namespace pfcp

#endif  // FILE_PFCP_QER_HPP_SEEN
