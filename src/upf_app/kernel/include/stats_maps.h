/* SPDX-License-Identifier: GPL-2.0 */
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
 * Changes:     Boy Scout cleanup — split xdp_stats_kern.h into
 *              stats_maps.h (BPF map + helper, this file) and
 *              stats_types.h (plain-C types).
 *              No functional changes to map or helper content.
 */
// clang-format on

/**
 * @file  stats_maps.h
 * @brief BPF map and action-recording helper for XDP statistics.
 *
 * Provides:
 *   mc_stats                    -- PERCPU_ARRAY of per-action datarec counters
 *   xdp_stats_record_action()   -- inline helper called at every XDP verdict
 *
 * Depends on: stats_types.h
 *
 * Used by: all XDP programs (every program calls xdp_stats_record_action()
 *          on every packet verdict)
 */

#ifndef __STATS_MAPS_H__
#define __STATS_MAPS_H__

#include <bpf/bpf_helpers.h>
#include "utils/logger.h"
#include "stats_types.h"

/* ==========================================================================
 * mc_stats
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
} mc_stats SEC(".maps");

/* ==========================================================================
 * xdp_stats_record_action — inline verdict helper
 * ========================================================================== */

/**
 * @brief Record an XDP verdict in mc_stats and return the action.
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

  struct datarec* rec = bpf_map_lookup_elem(&mc_stats, &action);
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