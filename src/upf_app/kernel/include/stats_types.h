/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __STATS_TYPES_H__
#define __STATS_TYPES_H__

#include "custom_types.h"
#include <linux/bpf.h>

/* ==========================================================================
 * Per-action statistics record
 * ========================================================================== */

/**
 * @brief Per-CPU statistics record stored in mc_stats_map.
 *
 * One entry per XDP action (XDP_ABORTED, XDP_DROP, XDP_PASS,
 * XDP_TX, XDP_REDIRECT).  Updated without locks because
 * BPF_MAP_TYPE_PERCPU_ARRAY returns a CPU-local pointer and XDP
 * runs under softirq (no preemption).
 */
struct datarec {
  u64 rx_packets; /**< Number of packets that triggered this action */
  u64 rx_bytes;   /**< Total bytes of packets for this action       */
};

/* ==========================================================================
 * XDP action array size
 * ========================================================================== */

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

/* ==========================================================================
 * XDP action name table (userspace use only)
 * ========================================================================== */

// clang-format off
 static const char *xdp_action_names[XDP_ACTION_MAX] = {
   [XDP_ABORTED]  = "XDP_ABORTED",
   [XDP_DROP]     = "XDP_DROP",
   [XDP_PASS]     = "XDP_PASS",
   [XDP_TX]       = "XDP_TX",
   [XDP_REDIRECT] = "XDP_REDIRECT",
 };
// clang-format on

#endif /* __STATS_TYPES_H__ */