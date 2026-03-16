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
 *                - Section 7.5.2.4: §7.5.2.4 is Create FAR in V17.10.0;
 *                  the Create URR grouped IE table is at §7.5.2.6.
 *                  Fixed: §7.5.2.6.
 *              V17.10.0 struct additions — 2 active data-plane IEs added:
 *                - time_quota (§8.2.47): max allowed session duration for
 *                  quota-based time enforcement; previously absent.
 *                - dropped_dl_traffic_threshold (§8.2.49): reporting
 *                  threshold for dropped DL packets; previously absent.
 *              Control-plane / application-level IEs — added as comments:
 *                - quota_holding_time: post-depletion countdown timer;
 *                  managed by user-space state machine, not per-packet XDP.
 *                  §-ref unconfirmed against V17.10.0 — verify before use.
 *                - event_quota (§8.2.82): application-detection event signals;
 *                  XDP has no visibility into application-level events.
 *                - event_threshold (§8.2.83): same reason.
 *              §-ref correction:
 *                - time_threshold inline comment was incorrectly labelled
 *                  §8.2.49; §8.2.49 = Dropped DL Traffic Threshold in
 *                  V17.10.0.  Correct §-ref for Time Threshold is not yet
 *                  confirmed — inline comment stripped per Rule 12.
 *              Boy Scout cleanup:
 *                - Replaced bare block comment with changelog + clang-format
 *                  guards and @file Doxygen block.
 *                - "Section X.X.X" notation → §X.X.X throughout.
 *                - Replaced kernel-doc @field list with ///< §-ref inline
 *                  comments on every struct field.
 *                - urr_id is a scalar __u32 rather than struct urr_id —
 *                  valid for BPF use, ABI note added.
 *   ABI BREAK: adding new fields changes struct size.  Update ConvertUrr()
 *     in urr_xdp_user.cpp and the kernel urr_apply.c simultaneously.
 *   New IE headers (time_quota.h, dropped_dl_traffic_threshold.h,
 *     quota_holding_time.h, event_quota.h, event_threshold.h) must exist
 *     in kernel/ie/; create following the pattern of ie/time_threshold.h.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §7.5.2.6   Create URR grouped IE
 *              §8.2.54    URR ID         §8.2.53  Reporting Triggers
 *              §8.2.62    Measurement Method
 *              §8.2.72    Measurement Period
 *              §8.2.15    Monitoring Time
 *              §8.2.46    Volume Quota   §8.2.47  Time Quota
 *              §8.2.48    Volume Threshold
 *              §8.2.49    Dropped DL Traffic Threshold
 *              §8.2.82    Event Quota    §8.2.83  Event Threshold
 */
// clang-format on

/**
 * @file pfcp_urr.h
 * @brief Kernel/user-space shared struct for Usage Reporting Rule (URR)
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * BPF-compatible representation of the PFCP Create URR IE (§7.5.2.6).
 * Shared between the kernel BPF program (urr_apply.c) and the
 * user-space manager (urr_xdp_user.h).
 *
 * @warning Changing field order or types is an ABI break — kernel and
 *          user-space must be updated simultaneously.
 * @warning New fields added in this revision (V17.10.0 update) change
 *          the struct size.  ConvertUrr() in urr_xdp_user.cpp and the
 *          kernel urr_apply.c must be updated before enabling new fields.
 *
 * @see 3GPP TS 29.244 §7.5.2.6  — Create URR grouped IE
 * @see urr_xdp_user.h            — User-space URR map manager
 */

#ifndef _PFCP_URR_H
#define _PFCP_URR_H

#include "ie/reporting_triggers.h"
#include "ie/measurement_method.h"
#include "ie/measurement_period.h"
#include "ie/time_threshold.h"
#include "ie/time_quota.h" /* §8.2.47 — V17.10.0 addition */
#include "ie/monitoring_time.h"
/* Control-plane only — not used by urr_apply XDP program:
 * #include "ie/quota_holding_time.h"    post-depletion timer managed by
 * user-space
 */
#include "ie/dropped_dl_traffic_threshold.h" /* §8.2.49 — V17.10.0 addition */
#include "ie/group_ie/volume_threshold.h"
#include "ie/group_ie/volume_quota.h"
/* Control-plane / application-level only — not used by urr_apply XDP program:
 * #include "ie/quota_holding_time.h"    §-ref unconfirmed; post-depletion CP
 * timer #include "ie/event_quota.h"           §8.2.82; application-event
 * signals, not XDP-visible #include "ie/event_threshold.h"       §8.2.83; same
 * reason
 */

/**
 * @struct pfcp_urr
 * @brief Usage Reporting Rule — BPF map value  (§7.5.2.6)
 *
 * Written by URRProgram::Setup(); read by the urr_apply BPF program
 * for per-session volume and time accounting.
 * Volume counters are stored separately in urr_volume_map and updated
 * atomically by the data plane; this struct carries thresholds/triggers.
 *
 * V17.10.0 additions (active data-plane fields):
 *   time_quota, dropped_dl_traffic_threshold — require ConvertUrr() update.
 *
 * Control-plane / application-level IEs (not used by urr_apply XDP program):
 *   quota_holding_time  — post-depletion countdown timer; user-space state
 * machine only. event_quota         — application-detection event signals; XDP
 * has no visibility into application-level events (§8.2.82). event_threshold —
 * same reason (§8.2.83).
 */
struct pfcp_urr {
  __u32 urr_id;  ///< URR identifier (§8.2.54)
  struct reporting_triggers
      reporting_triggers;  ///< Volume/time/periodic trigger flags (§8.2.53)
  struct measurement_method
      measurement_method;  ///< Volume / Duration / Event (§8.2.62)
  struct measurement_period
      measurement_period;  ///< Periodic reporting interval (§8.2.72)
  struct time_threshold
      time_threshold;  ///< Time-based reporting threshold (§-ref unconfirmed —
                       ///< verify against V17.10.0)
  struct monitoring_time
      monitoring_time;  ///< Measurement start/reset timestamp (§8.2.15)
  struct volume_threshold
      volume_threshold;  ///< Volume reporting thresholds UL/DL/total (§8.2.48)
  struct volume_quota
      volume_quota;              ///< Volume usage quotas UL/DL/total (§8.2.46)
  struct time_quota time_quota;  ///< Maximum allowed usage duration (§8.2.47)
  struct dropped_dl_traffic_threshold
      dropped_dl_traffic_threshold;  ///< Dropped DL packet reporting threshold
                                     ///< (§8.2.49)
  /* Control-plane / application-level only — not read by urr_apply XDP program:
   * struct quota_holding_time quota_holding_time;  post-depletion CP timer
   * (§-ref unconfirmed) struct event_quota event_quota; application-event quota
   * ceiling (§8.2.82) struct event_threshold event_threshold; application-event
   * reporting trigger (§8.2.83)
   */
} __attribute__((packed));

#endif /* _PFCP_URR_H */
