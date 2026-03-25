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
 * Changes:     Boy Scout cleanup — replaced Unicode arrows/dashes with
 *              plain ASCII.
 *              Fixed PROG_SESSION_LOOKUP: split into PROG_SESSION_LOOKUP_IP
 *              and PROG_SESSION_LOOKUP_ETH (slots 0 and 1) to match the
 *              established pipeline architecture in tail_call_dispatch.h.
 *              All subsequent indices shifted by +1 accordingly.
 *              Removed redundant -> dashes becoming actual ->
 */
// clang-format on

/**
 * @file  tail_call_types.h
 * @brief Types and indices for the XDP tail-call dispatch infrastructure.
 *
 * Defines:
 *   - enum upf_prog_index       slot indices into tail_call_progs_map
 *   - struct packet_context     per-packet state passed between tail-call
 * stages
 *   - struct session_rule_flags per-session feature enable flags
 *
 * The tail-call chain is:
 *
 *   [N3/N6 entry point]
 *     -> PROG_SESSION_LOOKUP_IP  (0)  xdp_session_lookup_ip.c
 *     -> PROG_SESSION_LOOKUP_ETH (1)  xdp_session_lookup_eth.c
 *     -> PROG_PDR_MATCH          (2)  pdr_match.c
 *     -> PROG_FAR_APPLY          (3)  xdp_far_apply.c
 *     -> PROG_QER_APPLY          (4)  xdp_qer_apply.c   [enable_qos: yes]
 *     -> PROG_URR_APPLY          (5)  xdp_urr_apply.c   [enable_urr: yes]
 *     -> PROG_BAR_APPLY          (6)  xdp_bar_apply.c   [enable_bar: yes]
 *     -> PROG_MAR_APPLY          (7)  xdp_mar_apply.c   [enable_mar: yes]
 *
 * Optional slots (4-7) are populated only when the corresponding feature
 * is enabled in the YAML configuration. An empty PROG_ARRAY slot causes
 * bpf_tail_call() to return silently — execution continues in the calling
 * program, which then returns the current XDP verdict.
 *
 * Shared by both kernel (BPF) and userspace translation units.
 * Contains only plain-C types — no BPF map definitions.
 * BPF maps are in tail_call_maps.h.
 */

#ifndef __TAIL_CALL_TYPES_H__
#define __TAIL_CALL_TYPES_H__

#include "linux/custom_types.h"
#include "packet_context.h"

/* ==========================================================================
 * PROG_ARRAY slot indices
 * ========================================================================== */

/**
 * @brief Program indices into tail_call_progs_map (BPF_MAP_TYPE_PROG_ARRAY).
 *
 * Used as the key in:
 *   bpf_tail_call(ctx, &tail_call_progs_map, PROG_<NAME>);
 *
 * The userspace loader (xdp_upf_user.cpp) populates the corresponding
 * slots based on the feature flags in the YAML configuration.
 * Slots for disabled features are left empty.
 *
 * NOTE: IP and ETH session lookup occupy distinct slots (0 and 1)
 * because entry points choose which lookup to call based on the PDU
 * session type detected from the incoming packet.
 */
enum upf_prog_index {
  PROG_SESSION_LOOKUP_IP  = 0, /**< Always present -- IP PDU session lookup  */
  PROG_SESSION_LOOKUP_ETH = 1, /**< Always present -- ETH PDU session lookup */
  PROG_PDR_MATCH          = 2, /**< Always present -- PDR matching           */
  PROG_FAR_APPLY          = 3, /**< Always present -- forwarding action      */
  PROG_QER_APPLY          = 4, /**< enable_qos: yes -- QoS enforcement       */
  PROG_URR_APPLY          = 5, /**< enable_urr: yes -- usage reporting       */
  PROG_BAR_APPLY          = 6, /**< enable_bar: yes -- buffering action      */
  PROG_MAR_APPLY          = 7, /**< enable_mar: yes -- multi-access routing  */
  PROG_MAX                = 8, /**< Sentinel -- must equal number of entries */
};

/* ==========================================================================
 * Per-session feature flags
 * ========================================================================== */

/**
 * @brief Per-session feature enable flags stored in session_rules_enabled_map.
 *
 * Written by SessionProgramManager on session establishment and updated
 * on modification. Read by xdp_far_apply.c and subsequent stages to
 * decide whether to tail-call the next optional stage or skip it.
 */
struct session_rule_flags {
  u8 qer_enabled; /**< 1 if this session has an active QER rule */
  u8 urr_enabled; /**< 1 if this session has an active URR rule */
  u8 bar_enabled; /**< 1 if this session has an active BAR rule */
  u8 mar_enabled; /**< 1 if this session has an active MAR rule */
};

#endif /* __TAIL_CALL_TYPES_H__ */