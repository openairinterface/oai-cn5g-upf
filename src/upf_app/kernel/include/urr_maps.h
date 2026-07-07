/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __URR_MAPS_H__
#define __URR_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "urr_types.h"
#include "upf_map_limits.h"

/* ==========================================================================
 * urr_volume_counters_map
 * ========================================================================== */

/**
 * @brief Per-session URR volume and packet counters.
 *
 * Key:   __u64              SEID
 * Value: struct urr_volume  {ul/dl bytes, packets, dropped_dl_*}
 * Size:  MAX_PDU_SESSIONS
 *
 * Non-PERCPU HASH (not PERCPU_ARRAY) — we need cross-CPU totals for
 * threshold comparisons.  Updated atomically via __sync_fetch_and_add()
 * (BPF_ATOMIC_ADD, requires kernel ≥ 5.12).
 *
 * Zeroed by the control plane on session establishment.
 * Userspace reads at any time for Usage Reports without resetting.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct urr_volume);
} urr_volume_counters_map SEC(".maps");

/* ==========================================================================
 * urr_config_map
 * ========================================================================== */

/**
 * @brief Per-session URR threshold and quota configuration.
 *
 * Key:   __u64              SEID
 * Value: struct urr_config  {urr_id, triggers, thresholds, quotas, timing}
 * Size:  MAX_PDU_SESSIONS
 *
 * Written by SessionProgramManager on session establishment (§7.2.2)
 * and updated on session modification (§7.2.4) when URR IEs are present.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct urr_config);
} urr_config_map SEC(".maps");

/* ==========================================================================
 * urr_report_ringbuf_map
 * ========================================================================== */

/**
 * @brief Ring buffer for Usage Report events to userspace.
 *
 * Key:   n/a   (ring buffer — no key)
 * Size:  256 KB
 *
 * Producer: xdp_urr_apply_kern.c  — submits struct urr_report_event
 *           when a Reporting Trigger fires.
 * Consumer: xdp_urr_apply_user.cpp — polls and constructs PFCP
 *           Session Report Requests (§7.2.5) for the SMF.
 *
 * If the ring is full, bpf_ringbuf_reserve() returns NULL and the
 * report is silently dropped.  Size the ring relative to the maximum
 * expected reporting burst rate.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); /* 256 KB */
} urr_report_ringbuf_map SEC(".maps");

#endif /* __URR_MAPS_H__ */
