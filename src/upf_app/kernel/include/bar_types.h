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

/**
 * @file  bar_types.h
 * @brief Buffering Action Rule (BAR) data structures.
 *
 * Defines all types shared between xdp_bar_apply_kern.c and the
 * userspace consumer xdp_bar_apply_user.cpp:
 *
 *   - struct bar_config      CP-configured buffering parameters
 *   - struct bar_state       runtime buffering state (DDN tracking)
 *   - struct bar_ddn_event   DDN ringbuf event sent to userspace
 *
 * NOTE: ABI boundary: any change to bar_config or bar_state MUST be
 *     reflected in ConvertBar() in SessionProgramManager.cpp and in
 *     the DDN event consumer in xdp_bar_apply_user.cpp.
 *
 * Contains only plain-C types — no BPF map definitions.
 *
 * 3GPP Ref: 3GPP TS 29.244 V17.10.0
 *   §8.2.57   BAR ID
 *   §8.2.28   Downlink Data Notification Delay
 *   §8.2.29   DL Buffering Duration
 *   §8.2.100  Suggested Buffering Packets Count
 *   Table 7.5.8.2-1  Downlink Data Report IE within PFCP Session Report Request
 */

/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Refactoring — split into *_types.h / *_maps.h pairs,
 *              corrected 3GPP TS 29.244 V17.10.0 section references,
 *              removed Unicode symbols, applied Boy Scout cleanup.
 */

#ifndef __BAR_TYPES_H__
#define __BAR_TYPES_H__

#include <linux/types.h>

/* ==========================================================================
 * BAR configuration  (CP -> data plane)
 * ========================================================================== */

/**
 * @brief BAR configuration pushed by the control plane.
 *
 * Stored in bar_config_map (keyed by SEID).
 * Populated during PFCP Session Establishment (§7.5.2) or
 * Modification (§7.5.4) when a Create BAR / Update BAR IE is present.
 */
struct bar_config {
  __u32 bar_id;                   /**< BAR ID (§8.2.57)                     */
  __u16 suggested_buf_pkt_cnt;    /**< Suggested Buffering Packets Count
                                   *   (§8.2.100). 0 = no limit hint.
                                   *   SMF suggests how many DL packets
                                   *   the UPF should buffer per UE.       */
  __u8 dl_notification_delay_sec; /**< DL Data Notification Delay (§8.2.28)
                                   *   in seconds. 0 = no suppression,
                                   *   send DDN for every BUFFER event.    */
  __u8 pad;
};

/* ==========================================================================
 * BAR runtime state  (data plane, mutable)
 * ========================================================================== */

/**
 * @brief Per-session BAR runtime buffering state.
 *
 * Stored in bar_state_map (keyed by SEID).
 * Created (zeroed) by the control plane on session establishment.
 * Updated atomically by xdp_bar_apply_kern.c.
 *
 * When the SMF changes the FAR apply action from BUFF -> FORW (UE
 * becomes reachable), the control plane should reset or delete this
 * entry so that a fresh DDN is sent on the next DL packet burst.
 */
struct bar_state {
  __u64 last_ddn_ns;        /**< Timestamp of last DDN submitted (ns)    */
  __u32 buffered_pkt_count; /**< Packets buffered since last DDN         */
  __u8 notification_sent;   /**< 1 = at least one DDN has been sent      */
  __u8 pad[3];
};

/* ==========================================================================
 * DDN event  (data plane -> userspace)
 * ========================================================================== */

/**
 * @brief Downlink Data Notification (DDN) event submitted to the ringbuf.
 *
 * Produced by xdp_bar_apply_kern.c when a DL packet triggers a DDN.
 * Consumed by xdp_bar_apply_user.cpp, which constructs a PFCP Session
 * Report Request (§7.5.8) with a Downlink Data Report IE towards the SMF.
 *
 * 3GPP Ref: TS 29.244 §7.5.8          — PFCP Session Report Request
 *           TS 29.244 Table 7.5.8.2-1 — Downlink Data Report IE
 */
struct bar_ddn_event {
  __u64 seid;         /**< PFCP Session Endpoint Identifier         */
  __u32 bar_id;       /**< BAR ID (§8.2.57)                         */
  __u32 pdr_id;       /**< PDR that matched the triggering DL packet */
  __u64 timestamp_ns; /**< bpf_ktime_get_ns() at DDN generation      */
  __u32 ue_ip;        /**< UE IPv4 address (for logging)             */
  __u32 pad;
};

#endif /* __BAR_TYPES_H__ */
