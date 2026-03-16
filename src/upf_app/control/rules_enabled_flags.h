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
 * Changes:     V17.10.0 audit — fixed all four §-refs:
 *                - QER flag: §8.2.40-43 (wrong — those are Outer Header
 *                  Removal, Source Interface, Destination Interface, Apply
 *                  Action) → §8.2.7 (Gate Status), §8.2.8 (MBR), §8.2.9
 *                  (GBR), §8.2.75 (QER ID).
 *                - URR flag: §8.2.44-48 (wrong — those are Volume Threshold
 *                  through Monitoring Time) → §8.2.54 (URR ID).
 *                - BAR flag: §8.2.49-50 (wrong — those are Dropped DL
 *                  Traffic Threshold and Volume Quota) → §8.2.57 (BAR ID).
 *                - MAR flag: §8.2.74-76 (wrong — §8.2.74 is FAR ID, §8.2.75
 *                  is QER ID, §8.2.76 is Activate Predefined Rules) →
 *                  §8.2.123 (MAR ID).
 *              Boy Scout: added clang-format guards, version header, and
 *              cross-references to the grouped IE tables for each rule type.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/**
 * @file rules_enabled_flags.h
 * @brief Per-session rule enable bitmask flags (3GPP TS 29.244 V17.10.0)
 *
 * Shared between the BPF data path (tail-call skip-chain dispatch) and the
 * userspace control plane (SessionProgramManager).  Stored in
 * session_rules_enabled_map (key: SEID, value: flags bitmask).
 *
 * Replaces the old session_qos_enabled_map which only tracked QER.
 * The tail-call skip-chain uses these flags to bypass disabled programs
 * at zero cost (no tail call issued for disabled rule types).
 *
 * @see 3GPP TS 29.244 V17.10.0 §7.5.2  PFCP Session Establishment Request
 * @see 3GPP TS 29.244 V17.10.0 §7.5.4  PFCP Session Modification Request
 */

#ifndef __RULES_ENABLED_FLAGS_H__
#define __RULES_ENABLED_FLAGS_H__

// clang-format off
 
 /** @brief QER — QoS Enforcement Rule (gate + MBR/GBR rate shaping).
  *
  *  Relevant IEs (3GPP TS 29.244 V17.10.0):
  *    §8.2.75  QER ID         (Mandatory in Create QER — Table 7.5.2.5-1)
  *    §8.2.7   Gate Status    (Mandatory — UL/DL open or closed)
  *    §8.2.8   MBR            (Conditional — Maximum Bit Rate)
  *    §8.2.9   GBR            (Conditional — Guaranteed Bit Rate)
  *    §8.2.89  QFI            (Conditional — QoS Flow Identifier)
  *    §8.2.88  RQI            (Optional  — Reflective QoS Indication)
  */
 #define RULE_QER_ENABLED (1U << 0)
 
 /** @brief URR — Usage Reporting Rule (volume/time measurement).
  *
  *  Relevant IEs (3GPP TS 29.244 V17.10.0):
  *    §8.2.54  URR ID              (Mandatory — Table 7.5.2.4-1)
  *    TODO     Measurement Method  (Mandatory — VOLUM/DURAT/EVENT; §-ref TBD)
  *    TODO     Reporting Triggers  (Mandatory; §-ref TBD)
  *    TODO     Volume Threshold    (Conditional; §-ref TBD)
  *    TODO     Time Threshold      (Conditional; §-ref TBD)
  *    TODO     Monitoring Time     (Optional; §-ref TBD)
  *
  *  @note §-refs for URR sub-IEs beyond URR ID are not in our verified
  *        V17.10.0 §-ref map yet and will be filled in when the URR IE
  *        table is audited in a dedicated pass.
  */
 #define RULE_URR_ENABLED (1U << 1)
 
 /** @brief BAR — Buffering Action Rule (DL data notification for idle UEs).
  *
  *  Relevant IEs (3GPP TS 29.244 V17.10.0):
  *    §8.2.57  BAR ID                          (Mandatory — Table 7.5.2.6-1)
  *    §8.2.28  Downlink Data Notification Delay (Optional — N4 only)
  *    §8.2.100 Suggested Buffering Packets Count (Optional — Sxb/Sxc/N4)
  */
 #define RULE_BAR_ENABLED (1U << 2)
 
 /** @brief MAR — Multi-Access Rule (ATSSS access steering).
  *
  *  Relevant IEs (3GPP TS 29.244 V17.10.0):
  *    §8.2.123 MAR ID                  (Mandatory — Table 7.5.2.8-1)
  *    §8.2.126 Weight (AFAI)           (Conditional — per access steering)
  *    §8.2.127 Priority (AFAI)         (Conditional)
  *    §8.2.197 Steering Mode Indicator (Optional — TODO: not yet in OAI lib)
  */
 #define RULE_MAR_ENABLED (1U << 3)

// clang-format on

#endif /* __RULES_ENABLED_FLAGS_H__ */
