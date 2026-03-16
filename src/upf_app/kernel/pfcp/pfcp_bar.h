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
 * Changes:     V17.10.0 audit — fixed §-ref in file-level comment:
 *                - Section 7.5.2.6: §7.5.2.6 is Create URR in V17.10.0;
 *                  the Create BAR grouped IE table is at §7.5.2.7.
 *                  Fixed: §7.5.2.7.
 *              V17.10.0 struct audit — no active fields added:
 *                - mt_edt_control_information (§8.2.175): MT-EDT trigger
 *                  is a CP decision; added as comment for future use.
 *              Boy Scout cleanup:
 *                - Replaced bare block comment with changelog + clang-format
 *                  guards and @file Doxygen block.
 *                - "Section X.X.X" notation → §X.X.X throughout.
 *                - Replaced kernel-doc @field list with ///< §-ref inline
 *                  comments on every struct field.
 *                - Noted that bar_id is a scalar __u8 rather than a
 *                  struct bar_id — valid for BPF use, ABI note added.
 *   ABI BREAK: adding mt_edt_control_information changes struct size.
 *     Update ConvertBar() in bar_xdp_user.cpp and kernel bar_apply.c
 *     simultaneously.
 *   ie/mt_edt_control_information.h must exist in kernel/ie/; create
 *     following the pattern of ie/suggested_buffering_packets_count.h
 *     if missing.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §7.5.2.7   Create BAR grouped IE
 *              §8.2.57    BAR ID
 *              §8.2.28    DL Data Notification Delay
 *              §8.2.100   Suggested Buffering Packets Count
 *              §8.2.175   MT-EDT Control Information
 */
// clang-format on

/**
 * @file pfcp_bar.h
 * @brief Kernel/user-space shared struct for Buffering Action Rule (BAR)
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * BPF-compatible representation of the PFCP Create BAR IE (§7.5.2.7).
 * Shared between the kernel BPF program (bar_apply.c) and the
 * user-space manager (bar_xdp_user.h).
 *
 * BAR is referenced indirectly: a FAR with apply_action.buff=1 carries a
 * bar_id that indexes into bar_config_map for buffering control.
 *
 * @warning Changing field order or types is an ABI break — kernel and
 *          user-space must be updated simultaneously.
 * @warning New field added in this revision (V17.10.0 update) changes
 *          the struct size.  ConvertBar() in bar_xdp_user.cpp and the
 *          kernel bar_apply.c must be updated before enabling the new field.
 *
 * @see 3GPP TS 29.244 §7.5.2.7  — Create BAR grouped IE
 * @see bar_xdp_user.h            — User-space BAR map manager
 */

#ifndef _PFCP_BAR_H
#define _PFCP_BAR_H

#include "ie/dl_data_notification_delay.h"
#include "ie/suggested_buffering_packets_count.h"
/* Control-plane only — not used by bar_apply XDP program:
 * #include "ie/mt_edt_control_information.h"   §8.2.175; MT-EDT trigger is a CP
 * decision
 */

/**
 * @struct pfcp_bar
 * @brief Buffering Action Rule — BPF map value  (§7.5.2.7)
 *
 * Written by BARProgram::Setup(); read by the bar_apply BPF program
 * for DL packet buffering and DDN suppression control.
 *
 * @note dl_data_notification_delay.delay_value > 0 activates DDN
 *       suppression: the data plane skips duplicate notifications within
 *       the delay window (tracked in bar_state_map.last_ddn_ns).
 *
 * Control-plane-only IE (not used by bar_apply XDP program):
 *   mt_edt_control_information — the decision to initiate MT-EDT is taken
 *   by the CP (SMF/AMF); the XDP data path only buffers/forwards packets
 *   and does not drive the EDT state machine (§8.2.175).
 */
struct pfcp_bar {
  __u8 bar_id;  ///< BAR identifier — scalar __u8, not struct bar_id (§8.2.57)
  struct dl_data_notification_delay
      dl_data_notification_delay;  ///< DDN delay in seconds (§8.2.28)
  struct suggested_buffering_packets_count
      suggested_buffering_packets_count;  ///< Max DL packets to buffer
                                          ///< (§8.2.100)
  /* Control-plane only — not read by bar_apply XDP program:
   * struct mt_edt_control_information mt_edt_control_information;  §8.2.175
   */
} __attribute__((packed));

#endif /* _PFCP_BAR_H */
