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
 * @file  mar_maps.h
 * @brief BPF map definitions for Multi-Access Rule (MAR) / ATSSS processing.
 *
 * Provides:
 *   - mar_config_map         per-session CP-configured steering rule
 *   - mar_access_state_map   per-session RTT / liveness state
 *                            (maintained by userspace probe daemon)
 *
 * Included by upf_xdp_kern.c (skeleton exposure) and by
 * xdp_mar_apply_kern.c (which consumes the maps).
 * xdp_mar_apply_kern.c must NOT redefine these maps.
 *
 * Active only when enable_mar = true in the YAML configuration.
 * All max_entries = 1 are placeholders set at runtime via
 * bpf_map__set_max_entries() before skel->load().
 *
 * Depends on: mar_types.h
 *
 * 3GPP Ref: 3GPP TS 29.244 V17.10.0 §8.2.123–§8.2.127
 *           TS 23.501 §5.32 — ATSSS
 */

/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Refactoring — split into *_types.h / *_maps.h pairs,
 *              corrected 3GPP TS 29.244 V17.10.0 section references,
 *              removed Unicode symbols, applied Boy Scout cleanup.
 */

#ifndef __MAR_MAPS_H__
#define __MAR_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "mar_types.h"
#include "upf_map_limits.h"

/* ==========================================================================
 * mar_config_map
 * ========================================================================== */

/**
 * @brief Per-session MAR steering configuration.
 *
 * Key:   __u64              SEID
 * Value: struct mar_config  {mar_id, steer_mode, access paths, weights}
 * Size:  MAX_PDU_SESSIONS
 *
 * Written by SessionProgramManager when Create MAR (§7.5.2.8) or
 * Update MAR (§7.5.4.13) IEs are present in a PFCP message.
 * Only sessions with ATSSS capability have entries in this map.
 *
 * Read by xdp_mar_apply_kern.c on every packet to determine which
 * access path to use for forwarding.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct mar_config);
} mar_config_map SEC(".maps");

/* ==========================================================================
 * mar_access_state_map
 * ========================================================================== */

/**
 * @brief Per-session access-path RTT and liveness state.
 *
 * Key:   __u64                    SEID
 * Value: struct mar_access_state  {rtt_3gpp_ns, rtt_non3gpp_ns,
 *                                  rtt_updated_ns, status_3gpp,
 *                                  status_non3gpp}
 * Size:  MAX_PDU_SESSIONS
 *
 * Updated by the userspace probe daemon (ICMP / GTP-U echo measurements).
 * Read by xdp_mar_apply_kern.c for:
 *   - STEER_SMALLEST_DELAY:  compare rtt_3gpp_ns vs rtt_non3gpp_ns
 *   - STEER_ACTIVE_STANDBY:  check status_* for failover detection
 *   - STEER_PRIORITY_BASED:  check preferred-path availability
 *
 * The probe daemon is the sole writer; the XDP program is read-only.
 * No atomic operations are required on this map.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct mar_access_state);
} mar_access_state_map SEC(".maps");

#endif /* __MAR_MAPS_H__ */
