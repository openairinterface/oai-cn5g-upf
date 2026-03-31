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
  if (update.get(mbr.second)) mbr.first = true;
  if (update.get(gbr.second)) gbr.first = true;
  if (update.get(qfi.second)) qfi.first = true;
  if (update.get(rqi.second)) rqi.first = true;
  // TODO: Packet Rate, DL Flow Level Marking
  // if (update.get(packet_rate.second)) packet_rate.first = true;
  // if (update.get(dl_flow_level_marking.second)) dl_flow_level_marking.first =
  // true;

  return true;
}
