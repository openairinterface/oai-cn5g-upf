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
 * @file  urr_maps.h
 * @brief BPF map definitions for Usage Reporting Rule (URR) processing.
 *
 * Provides:
 *   - urr_volume_counters_map  per-session volume / packet counters
 *   - urr_config_map           per-session CP-configured thresholds
 *   - urr_report_ringbuf_map   kernel → userspace report events
 *
 * Included by upf_xdp_kern.c (so the skeleton exposes the maps to
 * the userspace loader) and by xdp_urr_apply_kern.c (which uses them).
 * xdp_urr_apply_kern.c must NOT redefine these maps.
 *
 * Active only when enable_urr = true in the YAML configuration.
 * The userspace loader (xdp_upf_user.cpp) guards GetMap() calls with
 * the urr_enabled flag so that a missing map never causes a crash
 * when URR is disabled.
 *
 * All max_entries = 1 are placeholders set at runtime via
 * bpf_map__set_max_entries() before skel->load().
 *
 * Depends on: urr_types.h
 *
 * 3GPP Ref: 3GPP TS 29.244 V17.10.0:
 *      §8.2.40 (Measurement Method),
 *      §8.2.41 (Usage Report Trigger),
 *      §8.2.42 (Measurement Period),
 *      §8.2.44 (Volume Measurement),
 *      §8.2.45 (Duration Measurement),
 *      §8.2.46 (Time of First Packet),
 *      §8.2.47 (Time of Last Packet),
 *      §8.2.48 (Quota Holding Time).
 *      §8.2.49 (Dropped DL Traffic Threashold),
 *      §8.2.50 (Volume Quota),
 *      §8.2.51 (Time Quota),
 *      §8.2.52 (Start Time),
 *      §8.2.53 (End Time),
 *      §8.2.54 (URR ID),
 *      §8.2.55 (Linked URR ID IE)
 */

/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Refactoring — split into *_types.h / *_maps.h pairs,
 *              corrected 3GPP TS 29.244 V17.10.0 section references,
 *              removed Unicode symbols, applied Boy Scout cleanup.
 */

#ifndef __URR_MAPS_H__
#define __URR_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "urr_types.h"

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
