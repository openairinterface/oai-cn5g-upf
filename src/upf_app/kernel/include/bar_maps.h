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
 * Written by BARProgram::Setup()/PopulateBarConfigMap() when a Create BAR IE
 * (§7.5.2.6) or Update BAR IE (§7.5.4.11) is present in a PFCP message.
 *
 * @note The plain __u64 key holds exactly one BAR per SEID. BARProgram::Setup
 *       rejects a session with more than one BAR rather than letting the
 *       extras overwrite the first.
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
 * Value: struct bar_state  {notify_epoch_ns, buffered_pkt_count,
 *                           notification_sent}
 * Size:  MAX_PDU_SESSIONS
 *
 * Created (zeroed) by BARProgram::InitBarStateMap on session establishment.
 * Updated atomically by xdp_bar_apply_kern.c.
 * Zeroed by BARProgram::ResetBarState when buffering starts or ends, when
 * the SMF never answers a DL Data Report, and when the maximum buffering
 * time (T_guard) expires.
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
