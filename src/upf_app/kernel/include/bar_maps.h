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
 * @file  bar_maps.h
 * @brief BPF map definitions for Buffering Action Rule (BAR) processing.
 *
 * Provides:
 *   - bar_config_map        per-session CP-configured buffering params
 *   - bar_state_map         per-session runtime DDN tracking state
 *   - bar_ddn_ringbuf_map   kernel → userspace DDN event notifications
 *
 * Included by upf_xdp_kern.c (skeleton exposure) and by
 * xdp_bar_apply_kern.c (which consumes the maps).
 * xdp_bar_apply_kern.c must NOT redefine these maps.
 *
 * Active only when enable_bar = true in the YAML configuration.
 * All max_entries = 1 are placeholders set at runtime.
 *
 * Depends on: bar_types.h
 *
 * 3GPP Ref: 3GPP TS 29.244 V17.10.0
 *   §8.2.57   BAR ID
 *   §8.2.28   Downlink Data Notification Delay
 *   §8.2.100  Suggested Buffering Packets Count
 */

/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Refactoring — split into *_types.h / *_maps.h pairs,
 *              corrected 3GPP TS 29.244 V17.10.0 section references,
 *              removed Unicode symbols, applied Boy Scout cleanup.
 */

#ifndef __BAR_MAPS_H__
#define __BAR_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bar_types.h"

/* ==========================================================================
 * bar_config_map
 * ========================================================================== */

/**
 * @brief Per-session BAR buffering configuration.
 *
 * Key:   __u64              SEID
 * Value: struct bar_config  {bar_id, suggested_buf_pkt_cnt,
 *                            dl_notification_delay_sec}
 * Size:  MAX_PDU_SESSIONS
 *
 * Written by SessionProgramManager when a Create BAR IE (§7.5.2.6)
 * or Update BAR IE (§7.5.4.11) is present in a PFCP message.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct bar_config);
} bar_config_map SEC(".maps");

/* ==========================================================================
 * bar_state_map
 * ========================================================================== */

/**
 * @brief Per-session DDN suppression and buffer overflow state.
 *
 * Key:   __u64             SEID
 * Value: struct bar_state  {last_ddn_ns, buffered_pkt_count, notification_sent}
 * Size:  MAX_PDU_SESSIONS
 *
 * Created (zeroed) by SessionProgramManager on session establishment.
 * Updated atomically by xdp_bar_apply_kern.c.
 * Reset by SessionProgramManager when the FAR apply action changes
 * from BUFF → FORW (UE becomes reachable again).
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct bar_state);
} bar_state_map SEC(".maps");

/* ==========================================================================
 * bar_ddn_ringbuf_map
 * ========================================================================== */

/**
 * @brief Ring buffer for DDN (Downlink Data Notification) events.
 *
 * Key:   n/a   (ring buffer — no key)
 * Size:  64 KB
 *
 * Producer: xdp_bar_apply_kern.c — submits struct bar_ddn_event when
 *           the first DL packet for an idle UE arrives, or when the
 *           notification delay window expires.
 * Consumer: xdp_bar_apply_user.cpp — polls and constructs PFCP Session
 *           Report Requests (§7.5.8) for the SMF.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 64 * 1024); /* 64 KB */
} bar_ddn_ringbuf_map SEC(".maps");

#endif /* __BAR_MAPS_H__ */
