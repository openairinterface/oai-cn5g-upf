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
 * @file tail_call_dispatch.h
 * @brief Tail call program indices, shared maps, and skip-chain dispatch
 *
 * The dispatch helpers implement a skip-chain: each program calls
 * dispatch_after_X() which walks pctx->rules_enabled to find the
 * next enabled program, skipping disabled ones with zero overhead.
 *
 * Processing chain order (fixed):
 *
 *   Entry → Session Lookup → PDR Match → FAR → [QER] → [URR] → [MAR]
 *                                          └───→ [BAR]  (BUFF only, terminal)
 *
 * Programs in brackets are conditional on RULE_*_ENABLED flags set during
 * PFCP Session Establishment (TS 29.244 §7.2.2).
 *
 * @see 3GPP TS 29.244 - PFCP Protocol
 */

#ifndef TAIL_CALL_DISPATCH_H
#define TAIL_CALL_DISPATCH_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "packet_context.h"

/* ========================================================================== */
/*                          PROGRAM INDEX ENUM                                */
/* ========================================================================== */

/**
 * @brief Tail call program array indices
 *
 * Fixed assignment. Entry points (N3/N6) are attached directly to
 * interfaces and are NOT in the tail call array.
 */
enum tail_call_prog_index {
  PROG_SESSION_LOOKUP_IP  = 0, /**< IP PDU session lookup    */
  PROG_SESSION_LOOKUP_ETH = 1, /**< ETH PDU session lookup   */
  PROG_PDR_MATCH          = 2, /**< PDR matching (§8.2.21)   */
  PROG_FAR_APPLY          = 3, /**< FAR application (§8.2.22)*/
  PROG_QER_APPLY          = 4, /**< QER enforcement (§8.2.40)*/
  PROG_URR_APPLY          = 5, /**< URR measurement (§8.2.44)*/
  PROG_BAR_APPLY          = 6, /**< BAR buffering (§8.2.49)  */
  PROG_MAR_APPLY          = 7, /**< MAR steering (§8.2.74)   */
  __PROG_MAX              = 8,
};

/* ========================================================================== */
/*                              BPF MAPS                                      */
/* ========================================================================== */

/**
 * tail_call_progs_map - BPF tail call program array
 * Size: 16 (allows future extensions)
 *
 * Populated by userspace loader with program FDs for each stage.
 * All tail call programs must share this map via bpf_map__reuse_fd()
 * or pinning.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 16);
} tail_call_progs_map SEC(".maps");

/**
 * packet_context_map - Per-CPU shared packet context
 * Size: 1 (single entry, per-CPU for lockless access)
 *
 * Stores the packet_context structure that is populated progressively
 * as the packet traverses the tail call chain.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct packet_context);
  __uint(max_entries, 1);
} packet_context_map SEC(".maps");

/**
 * session_rules_enabled_map - Per-session rule enable flags
 * Size: Runtime (MAX_PDU_SESSIONS)
 * Key:   SEID (__u64)
 * Value: Bitmask of RULE_*_ENABLED flags (__u32)
 *
 * Populated by control plane during PFCP Session Establishment
 * (TS 29.244 §7.2.2) or Modification (TS 29.244 §7.2.4).
 *
 * Replaces the old per-feature maps (session_qos_enabled_map, etc.)
 * with a single unified bitmask.
 *
 * Example (userspace):
 *   u64 seid = session->seid;
 *   u32 flags = RULE_QER_ENABLED | RULE_URR_ENABLED;
 *   bpf_map_update_elem(rules_enabled_fd, &seid, &flags, BPF_ANY);
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, __u32);
} session_rules_enabled_map SEC(".maps");

/* ========================================================================== */
/*                           BASIC MACROS                                     */
/* ========================================================================== */

/**
 * @brief Dispatch to a specific tail call program
 *
 * If the target program is not loaded in the array, bpf_tail_call()
 * silently returns and execution continues at the next instruction.
 */
#define TAIL_CALL_NEXT(ctx, prog) bpf_tail_call(ctx, &tail_call_progs_map, prog)

/**
 * @brief Retrieve the per-CPU packet context
 *
 * Returns a pointer to the packet_context structure, or NULL if the
 * map lookup fails (should never happen for a PERCPU_ARRAY).
 */
#define GET_PACKET_CONTEXT()                                                   \
  ({                                                                           \
    __u32 _key = 0;                                                            \
    (struct packet_context*) bpf_map_lookup_elem(&packet_context_map, &_key);  \
  })

/* ========================================================================== */
/*                   EXECUTE FINAL ACTION (terminal helper)                   */
/* ========================================================================== */

/**
 * @brief Execute the terminal XDP action from pctx->final_action
 *
 * Used by the last program in the chain or as fallback when all downstream
 * programs are disabled. Implemented as a macro because it references
 * redirect_interfaces_map and xdp_stats_record_action which must be
 * linked in each compilation unit.
 */
#define EXECUTE_FINAL_ACTION(ctx, pctx)                                        \
  do {                                                                         \
    switch ((pctx)->final_action) {                                            \
      case FINAL_ACTION_REDIRECT_UL:                                           \
        return xdp_stats_record_action(                                        \
            ctx, bpf_redirect_map(&redirect_interfaces_map, UPLINK, 0));       \
      case FINAL_ACTION_REDIRECT_DL:                                           \
        return xdp_stats_record_action(                                        \
            ctx, bpf_redirect_map(&redirect_interfaces_map, DOWNLINK, 0));     \
      case FINAL_ACTION_PASS_TO_TC:                                            \
        return xdp_stats_record_action(ctx, XDP_PASS);                         \
      case FINAL_ACTION_DROP:                                                  \
        return xdp_stats_record_action(ctx, XDP_DROP);                         \
      default:                                                                 \
        return xdp_stats_record_action(ctx, XDP_PASS);                         \
    }                                                                          \
  } while (0)

/* ========================================================================== */
/*                     SKIP-CHAIN DISPATCH HELPERS                            */
/* ========================================================================== */

/**
 * @brief Dispatch to the next enabled program after FAR
 *
 * Walks the chain FAR → [QER] → [URR] → [MAR] and tail-calls the
 * first enabled program. If none are enabled, returns without
 * tail-calling and the caller executes final_action directly.
 *
 * @param ctx         XDP context
 * @param flags       pctx->rules_enabled bitmask
 * @param qer_needed  true if this packet path requires QER processing
 *                    (i.e. QER-eligible traffic AND QER enabled)
 */
static __always_inline void dispatch_after_far(
    struct xdp_md* ctx, __u32 flags, bool qer_needed) {
  /* QER: only if this path needs it AND rule is enabled */
  if (qer_needed && (flags & RULE_QER_ENABLED))
    TAIL_CALL_NEXT(ctx, PROG_QER_APPLY);

  /* URR: skip QER, go straight to usage reporting if enabled */
  if (flags & RULE_URR_ENABLED) TAIL_CALL_NEXT(ctx, PROG_URR_APPLY);

  /* MAR: skip QER+URR, go straight to access steering if enabled */
  if (flags & RULE_MAR_ENABLED) TAIL_CALL_NEXT(ctx, PROG_MAR_APPLY);

  /* Nothing enabled downstream — caller executes final_action */
}

/**
 * @brief Dispatch to the next enabled program after QER
 *
 * Chain: QER → [URR] → [MAR] → execute
 */
static __always_inline void dispatch_after_qer(
    struct xdp_md* ctx, __u32 flags) {
  if (flags & RULE_URR_ENABLED) TAIL_CALL_NEXT(ctx, PROG_URR_APPLY);

  if (flags & RULE_MAR_ENABLED) TAIL_CALL_NEXT(ctx, PROG_MAR_APPLY);
}

/**
 * @brief Dispatch to the next enabled program after URR
 *
 * Chain: URR → [MAR] → execute
 */
static __always_inline void dispatch_after_urr(
    struct xdp_md* ctx, __u32 flags) {
  if (flags & RULE_MAR_ENABLED) TAIL_CALL_NEXT(ctx, PROG_MAR_APPLY);
}

#endif /* TAIL_CALL_DISPATCH_H */
