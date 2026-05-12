/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef TAIL_CALL_DISPATCHER_H
#define TAIL_CALL_DISPATCHER_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "tail_call_types.h"
#include "tail_call_maps.h"
#include "stats_maps.h"
#include "packet_context.h"

/* ========================================================================== */
/*            TAIL_CALL_NEXT -- dispatch to a named program slot              */
/* ========================================================================== */

/**
 * @brief Tail-call into the next pipeline program.
 *
 * Wraps bpf_tail_call(ctx, &tail_call_progs_map, prog).
 * If the slot is empty (program not loaded), bpf_tail_call() is a
 * silent no-op and execution continues at the next statement.
 *
 * Usage:
 *   TAIL_CALL_NEXT(ctx, PROG_PDR_MATCH);
 */
#define TAIL_CALL_NEXT(ctx, prog) bpf_tail_call(ctx, &tail_call_progs_map, prog)

/* ========================================================================== */
/* GET_PACKET_CONTEXT -- retrieve per-CPU packet context                      */
/* ========================================================================== */

/**
 * @brief Retrieve the per-CPU packet context from packet_context_map.
 *
 * Returns a pointer to the current CPU's packet_context entry, or NULL
 * if the map lookup fails (should never happen for a PERCPU_ARRAY).
 *
 * Usage:
 *   struct packet_context *pctx = GET_PACKET_CONTEXT();
 *   if (!pctx) return xdp_stats_record_action(ctx, XDP_DROP);
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
 * @brief Execute the terminal XDP action stored in pctx->final_action.
 *
 * Called by the last enabled program in the chain, or as a fallback
 * when all downstream programs are disabled.
 *
 * Implemented as a macro because redirect_interfaces_map must be linked
 * in each compilation unit that calls it (DEVMAP lookup requires the map
 * to be present in the same BPF object).
 *
 * Usage:
 *   EXECUTE_FINAL_ACTION(ctx, pctx);
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
 * @brief Dispatch to the next enabled program after FAR.
 *
 * Walks the chain FAR -> [QER] -> [URR] -> [MAR] and tail-calls the
 * first enabled stage. If none are enabled, returns without tail-calling
 * so the caller can execute final_action directly.
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
 * @brief Dispatch to the next enabled program after QER.
 *
 * Chain: QER -> [URR] -> [MAR] -> execute
 *
 * @param ctx   XDP context.
 * @param flags pctx->rules_enabled bitmask.
 */
static __always_inline void dispatch_after_qer(
    struct xdp_md* ctx, __u32 flags) {
  if (flags & RULE_URR_ENABLED) TAIL_CALL_NEXT(ctx, PROG_URR_APPLY);

  if (flags & RULE_MAR_ENABLED) TAIL_CALL_NEXT(ctx, PROG_MAR_APPLY);
}

/**
 * @brief Dispatch to the next enabled program after URR.
 *
 * Chain: URR -> [MAR] -> execute
 *
 * @param ctx   XDP context.
 * @param flags pctx->rules_enabled bitmask.
 */
static __always_inline void dispatch_after_urr(
    struct xdp_md* ctx, __u32 flags) {
  if (flags & RULE_MAR_ENABLED) TAIL_CALL_NEXT(ctx, PROG_MAR_APPLY);
}

#endif /* TAIL_CALL_DISPATCHER_H */
