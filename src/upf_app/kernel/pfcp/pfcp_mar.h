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
 * Changes:     V17.10.0 audit — §7.5.2.8 is correct for Create MAR IE;
 *              no §-ref correction needed.
 *              V17.10.0 struct audit — structurally complete; no missing IEs.
 *              Boy Scout cleanup:
 *                - Replaced bare block comment with changelog + clang-format
 *                  guards and @file Doxygen block.
 *                - "Section X.X.X" notation → §X.X.X throughout.
 *                - Replaced kernel-doc @field list with ///< §-ref inline
 *                  comments on every struct field.
 *                - Noted that mar_id is a scalar __u16 rather than a
 *                  struct mar_id — valid for BPF use, ABI is frozen.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §7.5.2.8   Create MAR grouped IE
 *              §8.2.123   MAR ID
 *              §8.2.124   Steering Functionality
 *              §8.2.125   Steering Mode
 *              §8.2.126   AFAI Weight     §8.2.127  AFAI Priority
 */
// clang-format on

/**
 * @file pfcp_mar.h
 * @brief Kernel/user-space shared struct for Multi-Access Rule (MAR)
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * BPF-compatible representation of the PFCP Create MAR IE (§7.5.2.8).
 * MAR implements ATSSS (Access Traffic Steering, Switching and Splitting)
 * for distributing traffic across 3GPP (N3) and non-3GPP (N9/WLAN) accesses.
 * Shared between the kernel BPF program (mar_apply.c) and the
 * user-space manager (mar_xdp_user.h).
 *
 * @warning Changing field order or types is an ABI break — kernel and
 *          user-space must be updated simultaneously.
 *
 * @see 3GPP TS 29.244 §7.5.2.8  — Create MAR grouped IE
 * @see 3GPP TS 23.501 §5.32      — ATSSS
 * @see mar_xdp_user.h            — User-space MAR map manager
 */

#ifndef _PFCP_MAR_H
#define _PFCP_MAR_H

#include "ie/steering_functionality.h"
#include "ie/steering_mode.h"
#include "ie/group_ie/access_forwarding_action_info.h"

/**
 * @struct pfcp_mar
 * @brief Multi-Access Rule — BPF map value  (§7.5.2.8)
 *
 * Written by MARProgram::Setup(); read by the mar_apply BPF program
 * for ATSSS packet steering.  The two AFAI entries correspond to the
 * 3GPP access (N3) and non-3GPP access (N9/WLAN) respectively,
 * as named in §7.5.2.8.
 *
 * Steering modes (§8.2.125):
 *   STEER_ACTIVE_STANDBY — traffic to active access, failover to standby
 *   STEER_SMALLEST_DELAY — traffic to access with smaller RTT
 *   STEER_LOAD_BALANCE   — traffic split by weight (§8.2.126)
 *   STEER_PRIORITY_BASED — traffic to highest-priority access (§8.2.127)
 */
struct pfcp_mar {
  __u16 mar_id;  ///< MAR identifier (§8.2.123)
  struct steering_functionality
      steering_functionality;  ///< ATSSS-LL / MPTCP (§8.2.124)
  struct steering_mode
      steering_mode;  ///< Active-Standby/Load-Balance/etc. (§8.2.125)
  struct access_forwarding_action_info
      access_forwarding_action_info_1;  ///< 3GPP access AFAI — weight §8.2.126
                                        ///< / priority §8.2.127
  struct access_forwarding_action_info
      access_forwarding_action_info_2;  ///< Non-3GPP access AFAI — weight
                                        ///< §8.2.126 / priority §8.2.127
} __attribute__((packed));

#endif /* _PFCP_MAR_H */
