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
 * Changes:     Boy Scout cleanup — split xdp_stats_kern_user.h into
 *              stats_types.h (plain-C types, this file) and
 *              stats_maps.h (BPF map + helper).
 *              No functional changes to struct or constant content.
 */
// clang-format on

/**
 * @file  stats_types.h
 * @brief XDP statistics type definitions shared between kernel and userspace.
 *
 * Defines the per-action statistics record and action name table
 * used by the XDP statistics PERCPU_ARRAY map.
 *
 * Contains only plain-C types — no BPF map definitions.
 * The BPF map and xdp_stats_record_action() helper are in stats_maps.h.
 *
 * Used by: all XDP programs (via stats_maps.h),
 *          userspace statistics collector
 */

#ifndef __STATS_TYPES_H__
#define __STATS_TYPES_H__

#include "linux/custom_types.h"
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