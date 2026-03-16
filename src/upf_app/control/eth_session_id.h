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
 * Changes:     Boy Scout — added OAI license header; Doxygen on struct and
 *              all fields; corrected §-ref to TS 23.501 §5.6.10.3 for ETH PDU
 *              session type.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              3GPP TS 29.281 V17.3.0  (Release 17, 2022-12) — GTPv1-U
 *              3GPP TS 23.501          (Release 17)           — 5G System Arch.
 */
// clang-format on

/*! \file eth_session_id.h
   \brief   BPF map value for Ethernet PDU session TEID → session identity.
   \author  Franck Messaoudi
   \date    2026
   \email   franck.messaoudi@eurecom.fr

   Unlike IP PDU sessions (keyed by UE IP address in session_by_ue_ip_map),
   Ethernet PDU sessions carry no routable UE IP in the payload.
   The BPF map eth_session_mapping_map is therefore keyed by Uplink TEID.

   Reference: 3GPP TS 23.501 §5.6.10.3 — Ethernet PDU Session Type
*/

#ifndef __ETH_SESSION_ID_H__
#define __ETH_SESSION_ID_H__

#include "linux/custom_types.h"

/** @brief BPF map value for an Ethernet PDU session (key: uplink TEID).
 *
 *  Stored in eth_session_mapping_map.  Unlike IP PDU sessions keyed by UE IP
 *  (session_by_ue_ip_map), Ethernet PDU sessions use the uplink TEID as the
 *  primary lookup key since there is no routable UE IP in the payload.
 *
 *  @see 3GPP TS 23.501 §5.6.10.3 — Ethernet PDU Session Type
 *  @see 3GPP TS 29.281 §5.1      — GTP-U TEID allocation
 *  @see 3GPP TS 29.244 §8.2.37   — F-SEID / SEID
 */
struct eth_session_id {
  u32 teid_ul;       ///< Uplink TEID   — UPF listens on N3 (TS 29.281 §5.1)
  u32 teid_dl;       ///< Downlink TEID — GTP-U encapsulation toward gNB
  u32 ipv4_address;  ///< gNB outer IP  — outer header creation destination
  u64 seid;  ///< PFCP SEID     — Session Endpoint Identifier (§8.2.37)
};

#endif /* __ETH_SESSION_ID_H__ */
