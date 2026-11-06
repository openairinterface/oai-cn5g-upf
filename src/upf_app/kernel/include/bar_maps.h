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
 *                            dl_notification_delay_50ms, notify_cp}
 * Size:  MAX_PDU_SESSIONS
 *
 * Written by BARProgram::Setup() (the session has a BAR) or
 * BARProgram::SetupWithoutBar() (a BUFF FAR without a BAR), on every
 * Establishment or Modification that leaves RULE_BAR_ENABLED set.
 *
 * @note Keyed by SEID, so one BAR per session: Setup() uses the first BAR
 *       and logs and ignores the others.
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
 * Value: struct bar_state  {last_ddn_ns, buffered_pkt_count,
 *                           notification_sent}
 * Size:  MAX_PDU_SESSIONS
 *
 * Created (zeroed) by BARProgram::InitBarStateMap the first time the session
 * is set up with the BAR stage (BPF_NOEXIST), or by xdp_bar_apply_kern.c if
 * it is still missing. Updated atomically by xdp_bar_apply_kern.c.
 * Zeroed by BARProgram::ResetBarState when buffering starts or ends, when a
 * Downlink Data Report could not be queued (BarDdnConsumer), when the SMF
 * never answers one, when the maximum hold time expires while packets are
 * held, and at the next DL buffer tick after the report of a replayed packet
 * could not be queued. Erased by BARProgram::Remove when the session is
 * deleted.
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
 * Producer: xdp_bar_apply_kern.c submits a struct bar_ddn_event when a DL
 *           packet reaches the BAR program with bar_config.notify_cp set
 *           and the notification latch clear, or, with a non-zero
 *           Downlink Data Notification Delay, at least that delay after
 *           the last DDN.
 * Consumer: control/BarDdnConsumer.cpp, which turns each well-formed
 *           event of a live session into a PFCP Session Report Request
 *           (§7.5.8) with a Downlink Data Report for the SMF.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 64 * 1024); /* 64 KB */
} bar_ddn_ringbuf_map SEC(".maps");

/* ==========================================================================
 * xskmap
 * ========================================================================== */

/**
 * @brief AF_XDP sockets that receive the packets BAR holds (DL buffering).
 *
 * Key:   __u32  N6 RX queue index (ctx->rx_queue_index)
 * Value: __u32  AF_XDP socket fd, one per N6 RX queue
 * Size:  fixed 64 (BARProgram::ConfigureMaps, before load)
 *
 * Filled by XskConsumer when DL buffering is enabled. A packet sent to an
 * empty slot is dropped (XDP_DROP fallback).
 */
struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 1); /* Runtime: BARProgram::kXskMapMaxEntries (64) */
  __type(key, __u32);
  __type(value, __u32);
} xskmap SEC(".maps");

#endif /* __BAR_MAPS_H__ */
