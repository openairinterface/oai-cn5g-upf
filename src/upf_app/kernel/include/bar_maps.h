/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __BAR_MAPS_H__
#define __BAR_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bar_types.h"
#include "upf_map_limits.h"

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
