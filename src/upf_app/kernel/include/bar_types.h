/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __BAR_TYPES_H__
#define __BAR_TYPES_H__

#include <linux/types.h>

/* ==========================================================================
 * BAR configuration  (CP -> data plane)
 * ========================================================================== */

/**
 * @brief BAR configuration pushed by the control plane.
 *
 * Stored in bar_config_map (keyed by SEID).
 * Written on every PFCP Session Establishment (§7.5.2) or Modification
 * (§7.5.4) that leaves RULE_BAR_ENABLED set, whether or not it carries a
 * Create BAR / Update BAR IE: by Setup() from the session's BAR,
 * or, for a BUFF FAR without a BAR, a default entry (bar_id 0, no limits)
 * written by SetupWithoutBar().
 *
 * Model limits: one bar_config and one bar_state per SEID, so one BAR and
 * one notification latch per session. A second buffering PDR in the same
 * session shares that latch: its packets trigger no DDN of their own until
 * the latch is re-armed or, with a non-zero Downlink Data Notification
 * Delay, until that delay has passed since the last DDN. TS 29.244 §5.2.3.1
 * asks for a report per QoS flow and FAR in 5GC.
 */
struct bar_config {
  /**
   * BAR ID is one octet (§8.2.57), held in a __u32. 0 is also used for the
   * default config of a session without a BAR.
   */
  __u32 bar_id;
  /**
   * Suggested Buffering Packets Count (§8.2.100). 0 = no limit. Applied to
   * DL packets only, against buffered_pkt_count (see bar_state); TS 29.244
   * counts UL and DL packets per PFCP session.
   */
  __u16 suggested_buf_pkt_cnt;
  /**
   * Downlink Data Notification Delay (§8.2.28), in 50 ms units as in the IE.
   * UPF-specific use: TS 29.244 defines it as a delay between receiving a DL
   * packet and notifying the CP function; the BAR program submits the first
   * DDN at once and uses the value as the minimum gap before a repeat DDN.
   * 0 = no repeat until the notification latch is re-armed. The UPF does not
   * advertise the DDND feature.
   */
  __u8 dl_notification_delay_50ms;
  /**
   * 1 = the CP function asked to be notified (Apply Action NOCP, §8.2.26).
   * Setup() sets it when a FAR that references this BAR has NOCP, without
   * checking BUFF; SetupWithoutBar() sets it for a FAR with both BUFF and
   * NOCP. TS 29.244 §8.2.26 allows NOCP only together with BUFF, so the
   * two rules agree for a compliant SMF. Set by the UPF, not carried in the
   * BAR IE.
   */
  __u8 notify_cp;
};
/* sizeof(struct bar_config) == 8 — asserted on the userspace side in
 * user/bar_apply_user.h, so that the kernel and userspace layouts match. */

/* ==========================================================================
 * bar_state.last_ddn_ns sentinels (see struct bar_state below)
 * ========================================================================== */

/**
 * @brief No DDN submitted since the entry was created or the notification
 *        latch was last re-armed.
 */
#define NOTIFY_FREE 0ULL

/**
 * @brief High-bit sentinel: one CPU is submitting a DDN. A send time from
 *        bpf_ktime_get_ns() never has the high bit set, so it never equals
 *        this value.
 */
#define NOTIFY_CLAIMED 0x8000000000000000ULL

/* ==========================================================================
 * BAR runtime state  (data plane, mutable)
 * ========================================================================== */

/**
 * @brief Per-session BAR runtime buffering state.
 *
 * Stored in bar_state_map (keyed by SEID).
 * Created (zeroed) by the control plane the first time the session is set up
 * with the BAR stage, or by xdp_bar_apply_kern.c if it is still missing.
 * Updated atomically by xdp_bar_apply_kern.c.
 *
 * Notification latch: last_ddn_ns. 0 (NOTIFY_FREE) = no DDN submitted since
 * the entry was created or the latch was last re-armed. NOTIFY_CLAIMED = one
 * CPU is submitting a DDN. Any other value = time of the last DDN submitted
 * (bpf_ktime_get_ns(), bit 63 clear). Re-armed (zeroed) by
 * BARProgram::ResetBarState(); restored to its previous value by the XDP BAR
 * program when the ring buffer is full; erased with the session by
 * BARProgram::Remove().
 *
 * Reset points: see bar_state_map in bar_maps.h.
 */
struct bar_state {
  /**
   * Notification latch (see above). 64-bit: it holds a bpf_ktime_get_ns()
   * send time, and a 32-bit nanosecond count wraps after about 4.29 s, less
   * than the longest Downlink Data Notification Delay (255 x 50 ms = 12.75 s).
   * Bit 63 is the NOTIFY_CLAIMED sentinel.
   */
  __u64 last_ddn_ns;
  /**
   * DL packets that reached the BAR program's buffer-limit step since this
   * entry was created or last reset, including those then dropped.
   */
  __u32 buffered_pkt_count;
  /**
   * 1 iff last_ddn_ns holds a send time. A mirror for bpftool readers only;
   * not the latch.
   */
  __u8 notification_sent;
  __u8 pad[3];
};
/* sizeof(struct bar_state) == 16, naturally 8-byte aligned — asserted on the
 * userspace side in user/bar_apply_user.h. */

/* ==========================================================================
 * DDN event  (data plane -> userspace)
 * ========================================================================== */

/**
 * @brief Downlink Data Notification (DDN) event submitted to the ringbuf.
 *
 * Produced by xdp_bar_apply_kern.c when a DL packet triggers a DDN.
 * Consumed by control/BarDdnConsumer.cpp, which constructs a PFCP Session
 * Report Request (§7.5.8) with a Downlink Data Report IE towards the SMF.
 *
 * DDN event (XDP ring) → PFCP Session Report Request, Report Type DLDR
 * + Downlink Data Report IE → 'Data Notification' in TS 23.502 §4.2.3.3
 * step 2a.
 *
 * 3GPP Ref: TS 29.244 §7.5.8          — PFCP Session Report Request
 *           TS 29.244 Table 7.5.8.2-1 — Downlink Data Report IE
 */
struct bar_ddn_event {
  __u64 seid;         /**< PFCP Session Endpoint Identifier         */
  __u32 bar_id;       /**< BAR ID (§8.2.57)                         */
  __u32 pdr_id;       /**< PDR ID (16-bit Rule ID, §8.2.36) of the PDR
                       *   that matched the triggering DL packet     */
  __u64 timestamp_ns; /**< bpf_ktime_get_ns() at DDN generation      */
  __u32 ue_ip;        /**< UE IPv4 address in host byte order
                       *   (for logging)                             */
  __u32 pad;
};

#endif /* __BAR_TYPES_H__ */
