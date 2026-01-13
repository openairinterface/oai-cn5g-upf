/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pfcp_qer.hpp"
#include "pfcp_switch.hpp"
#include "upf_config.hpp"
#include "simple_switch.hpp"

using namespace pfcp;

//------------------------------------------------------------------------------
bool pfcp_qer::update(const pfcp::update_qer& update, uint8_t& cause_value) {
  if (update.get(qer_id.second)) qer_id.first = true;
  if (update.get(qer_correlation_id.second)) qer_correlation_id.first = true;
  if (update.get(gate_status.second)) gate_status.first = true;
  if (update.get(maximum_bitrate.second)) maximum_bitrate.first = true;
  if (update.get(guaranteed_bitrate.second)) guaranteed_bitrate.first = true;
  if (update.get(qos_flow_id.second)) qos_flow_id.first = true;
  if (update.get(reflective_qos.second)) reflective_qos.first = true;
  if (update.get(paging_policy_indicator.second))
    paging_policy_indicator.first = true;
  if (update.get(averaging_window.second)) averaging_window.first = true;
  return true;
}
