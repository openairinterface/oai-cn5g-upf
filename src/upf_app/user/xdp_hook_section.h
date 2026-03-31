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
 * Changes:     New file. Provides:
 *              global varaible for xdp
 *              hooked sections
 */
// clang-format on

/**
 * @file  xdp_stage_program.h
 * @brief CRTP base template for XDP pipeline stage programs.
 * @author Franck Messaoudi
 * @date 2026-03
 *
 * Eliminates magic hardcodded values
 *
 */

#ifndef XDP_HOOK_SECTION_H_
#define XDP_HOOK_SECTION_H_

#include <string>

class XDPSection {
 public:
  static constexpr const char* Uplink_IP_PDU_SESSION =
      "xdp_n3_entry";  ///< GTP-U uplink for IP PDU Session
  static constexpr const char* Downlink_IP_PDU_SESSION =
      "xdp_n6_entry";  ///< Downlink for IP PDU Session
  static constexpr const char* Uplink_ETH_PDU_SESSION =
      "xdp_n3_eth_entry";  ///< GTP-U uplink for ETH PDU Session
  static constexpr const char* Downlink_ETH_PDU_SESSION =
      "xdp_n6_eth_entry";  ///< Downlink for ETH PDU Session
};

#endif  // XDP_HOOK_SECTION_H_