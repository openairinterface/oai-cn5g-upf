/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __STATS_MAPS_H__
#define __STATS_MAPS_H__

#include <bpf/bpf_helpers.h>
#include "utils/logger.h"
#include "stats_types.h"

/* ==========================================================================
 * mc_stats_map
 * ========================================================================== */

/**
 * @brief Per-CPU per-action statistics array.
 *
 * Key:   u32            XDP action index (XDP_ABORTED .. XDP_REDIRECT)
 * Value: struct datarec {rx_packets, rx_bytes}
 * Size:  XDP_ACTION_MAX (5)
 *
 * BPF_MAP_TYPE_PERCPU_ARRAY returns a CPU-local record; updates
 * are safe without atomic operations since XDP runs under softirq.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, XDP_ACTION_MAX);
  __type(key, __u32);
  __type(value, struct datarec);
} mc_stats_map SEC(".maps");

/* ==========================================================================
 * xdp_stats_record_action — inline verdict helper
 * ========================================================================== */

/**
 * @brief Record an XDP verdict in mc_stats_map and return the action.
 *
 * Called as the final return in every XDP program:
 *   return xdp_stats_record_action(ctx, XDP_PASS);
 *
 * @param ctx    XDP metadata context (used for byte count)
 * @param action XDP verdict to record and return
 * @return action (or XDP_ABORTED on internal error)
 */
static __u32 xdp_stats_record_action(struct xdp_md* ctx, __u32 action) {
  if (action >= XDP_ACTION_MAX) {
    bpf_debug("stats: invalid action %u\n", action);
    return XDP_ABORTED;
  }

  struct datarec* rec = bpf_map_lookup_elem(&mc_stats_map, &action);
  if (!rec) {
    bpf_debug("stats: map lookup failed for action %u\n", action);
    return XDP_ABORTED;
  }

  /* PERCPU_ARRAY + softirq context = safe without atomics */
  rec->rx_packets++;
  rec->rx_bytes += (ctx->data_end - ctx->data);

  return action;
}

#endif /* __STATS_MAPS_H__ */