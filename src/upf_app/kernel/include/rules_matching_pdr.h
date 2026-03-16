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
 * @file rules_matching_pdr.h
 * @brief Per-PDR rule association for BPF data path
 *
 * Maps a matched PDR (key: {pdr_id, seid}) to the complete set of
 * rules that apply to packets matching that PDR. Stored in:
 *   - rules_match_pdr_map (IP PDU sessions)
 *   - eth_rules_match_pdr_map (Ethernet PDU sessions)
 *
 * The tail call chain uses this struct as follows:
 *   PDR Match -> FAR Apply (reads rules->far)
 *             -> QER Apply (reads rules->qer)
 *             -> URR Apply (reads rules->urr, runtime state in urr_volume_map)
 *             -> BAR Apply (reads rules->bar, runtime state in bar_state_map)
 *             -> MAR Apply (reads rules->mar)
 *
 * @see 3GPP TS 29.244 Section 8.2 — Information Elements
 * @see 3GPP TS 29.244 Section 7.2.2 — PFCP Session Establishment
 */

#ifndef __RULES_MATCHING_PDR_H__
#define __RULES_MATCHING_PDR_H__

#include "linux/custom_types.h"
#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_qer.h"
#include "pfcp/pfcp_urr.h"
#include "pfcp/pfcp_bar.h"
#include "pfcp/pfcp_mar.h"

/**
 * @struct rules_match_pdr
 * @brief Complete rule set associated with a matched PDR
 *
 * Populated by control plane (SessionProgramManager::CreatePipeline /
 * ModifyPipeline) and read by each tail call program in the chain.
 *
 * All five rule types from 3GPP TS 29.244:
 *   - FAR: Forwarding Action (mandatory, Section 8.2.22-26)
 *   - QER: QoS Enforcement   (optional,  Section 8.2.40-43)
 *   - URR: Usage Reporting   (optional,  Section 8.2.44-48)
 *   - BAR: Buffering Action  (optional,  Section 8.2.49-50)
 *   - MAR: Multi-Access Rule (optional,  Section 8.2.74-76)
 *
 * URR/BAR runtime state (volume counters, buffered pkt count) is
 * stored separately in urr_volume_map / bar_state_map since it is
 * updated atomically by the data path and must not be overwritten
 * by control plane session modifications.
 */
struct rules_match_pdr {
  struct pfcp_far far; /* Forwarding Action Rule (Section 8.2.22)  */
  struct pfcp_qer qer; /* QoS Enforcement Rule   (Section 8.2.40)  */
  struct pfcp_urr urr; /* Usage Reporting Rule   (Section 8.2.44)  */
  struct pfcp_bar bar; /* Buffering Action Rule  (Section 8.2.49)  */
  struct pfcp_mar mar; /* Multi-Access Rule      (Section 8.2.74)  */
};

/**
 * @struct pdrs_per_session
 * @brief Key for rules_match_pdr_map and eth_rules_match_pdr_map
 *
 * Combines PDR ID with SEID to uniquely identify a rule set.
 * PDR IDs are unique within a session but not globally.
 */
struct pdrs_per_session {
  u16 pdr_id; /* PDR ID (Section 8.2.21)                   */
  u64 seid;   /* Session Endpoint Identifier               */
};

#endif /* __RULES_MATCHING_PDR_H__ */