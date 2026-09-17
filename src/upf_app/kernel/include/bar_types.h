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
 * Populated during PFCP Session Establishment (§7.5.2) or
 * Modification (§7.5.4) when a Create BAR / Update BAR IE is present.
 */
struct bar_config {
  __u32 bar_id;                    /**< BAR ID (§8.2.57)                    */
  __u16 suggested_buf_pkt_cnt;     /**< Suggested Buffering Packets Count
                                    *   (§8.2.100). 0 = no limit hint.
                                    *   SMF suggests how many DL packets
                                    *   the UPF should buffer per UE.      */
  __u8 dl_notification_delay_50ms; /**< DL Data Notification Delay (§8.2.28)
                                    *   in units of 50 ms, copied verbatim
                                    *   from the PFCP IE (no lossy rounding
                                    *   to seconds).
                                    *   0 = one-shot per idle burst: the
                                    *   first DDN commits an epoch and every
                                    *   later packet takes the suppression
                                    *   branch; no re-notification until the
                                    *   state is reset on leaving BUFFER.
                                    *   Non-zero = re-notification is
                                    *   permitted once the delay window
                                    *   (value x 50 ms) has elapsed since the
                                    *   last committed DDN.                */
  __u8 notify_cp;                  /**< 1 = at least one FAR referencing this
                                    *   BAR has apply_action.nocp set, i.e.
                                    *   the CP asked to be notified
                                    *   (§8.2.26). Populated by UPF;
                                    *   reuses the former pad byte.        */
};
/* sizeof(struct bar_config) == 8 — asserted userspace-side in
 * user/bar_apply_user.h; keep the kernel and userspace views in lockstep. */

/* ==========================================================================
 * bar_state.notify_epoch_ns sentinels (see struct bar_state below)
 * ========================================================================== */

/** @brief No DDN committed and none in flight. */
#define NOTIFY_FREE 0ULL

/**
 * @brief High-bit sentinel: a CPU claimed the notification window and a ring
 *        submit is in flight. A real bpf_ktime_get_ns() epoch never sets the
 *        high bit, so this value can never collide with a committed epoch.
 */
#define NOTIFY_CLAIMED 0x8000000000000000ULL

/* ==========================================================================
 * BAR runtime state  (data plane, mutable)
 * ========================================================================== */

/**
 * @brief Per-session BAR runtime buffering state.
 *
 * Stored in bar_state_map (keyed by SEID).
 * Created (zeroed) by the control plane on session establishment.
 * Updated atomically by xdp_bar_apply_kern.c.
 *
 * When the SMF changes the FAR apply action from BUFF -> FORW (UE
 * becomes reachable), the control plane should reset or delete this
 * entry so that a fresh DDN is sent on the next DL packet burst.
 */
struct bar_state {
  __u64 notify_epoch_ns;    /**< 64-bit atomic claim/epoch word — the ONLY
                             *   __sync_* operand (8/32-bit __sync_* does not
                             *   compile for the BPF target).
                             *   NOTIFY_FREE (0) = no DDN committed or in
                             *   flight; NOTIFY_CLAIMED = a CPU claimed the
                             *   window, submit in flight; any other value
                             *   (high bit clear, nonzero) = committed DDN
                             *   epoch, i.e. the timestamp of the last
                             *   successful submit AND the DL-notification-
                             *   delay-window reference. Repurposes the
                             *   aligned __u64 slot that was last_ddn_ns —
                             *   same size/offset/alignment.              */
  __u32 buffered_pkt_count; /**< Packets buffered since last DDN          */
  __u8 notification_sent;   /**< DERIVED readback MIRROR (debug / bpftool /
                             *   tests only, NOT the atomic operand):
                             *   1 iff notify_epoch_ns holds a committed
                             *   epoch, else 0.                           */
  __u8 pad[3];
};
/* sizeof(struct bar_state) == 16, naturally 8-byte aligned — asserted
 * userspace-side in user/bar_apply_user.h. */

/* ==========================================================================
 * DDN event  (data plane -> userspace)
 * ========================================================================== */

/**
 * @brief Downlink Data Notification (DDN) event submitted to the ringbuf.
 *
 * Produced by xdp_bar_apply_kern.c when a DL packet triggers a DDN.
 * Consumed by xdp_bar_apply_user.cpp, which constructs a PFCP Session
 * Report Request (§7.5.8) with a Downlink Data Report IE towards the SMF.
 *
 * 3GPP Ref: TS 29.244 §7.5.8          — PFCP Session Report Request
 *           TS 29.244 Table 7.5.8.2-1 — Downlink Data Report IE
 */
struct bar_ddn_event {
  __u64 seid;         /**< PFCP Session Endpoint Identifier         */
  __u32 bar_id;       /**< BAR ID (§8.2.57)                         */
  __u32 pdr_id;       /**< PDR that matched the triggering DL packet */
  __u64 timestamp_ns; /**< bpf_ktime_get_ns() at DDN generation      */
  __u32 ue_ip;        /**< UE IPv4 address (for logging)             */
  __u32 pad;
};

#endif /* __BAR_TYPES_H__ */
