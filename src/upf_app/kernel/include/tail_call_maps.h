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
 * Changes:     Boy Scout cleanup — added OAI license header and section
 *              separators. Replaced Unicode dashes with plain ASCII.
 *              Fixed include: replaced pipeline_types.h with
 *              tail_call_types.h (packet_context is defined there, not
 *              in pipeline_types.h).
 */
// clang-format on

/**
 * @file  tail_call_maps.h
 * @brief BPF map definitions for the tail-call dispatch infrastructure.
 *
 * Provides:
 *   tail_call_progs_map       -- PROG_ARRAY for program dispatch
 *   packet_context_map        -- per-CPU packet state (cross-stage)
 *   session_rules_enabled_map -- per-session feature enable flags
 *
 * These maps are included by every entry-point and pipeline program.
 *
 * Depends on: tail_call_types.h
 *
 * NOTE: tail_call_progs_map (this file) is separate from
 * feature_dispatch_map (pipeline_maps.h). Both are PROG_ARRAYs used at
 * different call sites — they may be consolidated in a future cleanup.
 */

#ifndef __TAIL_CALL_MAPS_H__
#define __TAIL_CALL_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "tail_call_types.h"
#include "upf_xdp_limits.h"

/* ==========================================================================
 * .rodata — runtime-configurable size constants
 * ========================================================================== */

/**
 * Set by userspace via bpf_map__set_value_size() / skeleton globals
 * before skel->load(). Shared across all programs via .rodata section.
 */

const volatile int MAX_PDU_SESSIONS SEC(".rodata");

/* ==========================================================================
 * tail_call_progs_map
 * ========================================================================== */

/**
 * @brief PROG_ARRAY for pipeline tail-call dispatch.
 *
 * Key:   u32   enum upf_prog_index (PROG_SESSION_LOOKUP_IP .. PROG_MAR_APPLY)
 * Value: u32   BPF program file descriptor
 * Size:  MAX_TAIL_CALL_PROGS (16)
 *
 * Slots 0-3 are always populated. Slots 4-7 (QER/URR/BAR/MAR) are populated
 * only when the corresponding feature is enabled in the YAML configuration.
 * An empty slot makes bpf_tail_call() a silent no-op -- execution returns
 * to the caller, which returns the current XDP verdict.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, MAX_TAIL_CALL_PROGS);
  __type(key, u32);
  __type(value, u32);
} tail_call_progs_map SEC(".maps");

/* ==========================================================================
 * packet_context_map
 * ========================================================================== */

/**
 * @brief Per-CPU packet context -- cross-stage state.
 *
 * Key:   u32                   CPU ID (bpf_get_smp_processor_id())
 * Value: struct packet_context {seid, teid_ul, teid_dl, pdr_id, qfi ...}
 * Size:  MAX_CPUS (256)
 *
 * Written by session_lookup_{ip,eth}.c and pdr_match.c.
 * Read by xdp_far_apply.c and all subsequent tail-call stages.
 *
 * Using a plain ARRAY keyed by CPU ID avoids atomic operations since
 * each CPU exclusively owns its slot and XDP runs under softirq
 * (no preemption, no concurrent access to the same slot).
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_CPUS);
  __type(key, u32);
  __type(value, struct packet_context);
} packet_context_map SEC(".maps");

/* ==========================================================================
 * session_rules_enabled_map
 * ========================================================================== */

/**
 * @brief Per-session feature enable flags.
 *
 * Key:   u64                        SEID
 * Value: struct session_rule_flags  {qer_enabled, urr_enabled,
 *                                    bar_enabled, mar_enabled}
 * Size:  Runtime -- MAX_PDU_SESSIONS
 *
 * Written by SessionProgramManager on session establishment (§7.5.2)
 * and updated on modification (§7.5.4).
 * Read by xdp_far_apply.c and subsequent stages to decide whether to
 * tail-call the next optional stage or fall through to the verdict.
 *
 * Using a dedicated struct (rather than a bitmask) makes individual
 * flag checks explicit and avoids magic bit constants in kernel code.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u64);
  __type(value, struct session_rule_flags);
} session_rules_enabled_map SEC(".maps");

#endif /* __TAIL_CALL_MAPS_H__ */