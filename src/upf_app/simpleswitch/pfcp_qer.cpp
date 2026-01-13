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

/*! \file pfcp_qer.cpp
   \author  Franck MESSAOUDI
   \date 2024
   \email: franck.messaoudi@openairinterface.org
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
