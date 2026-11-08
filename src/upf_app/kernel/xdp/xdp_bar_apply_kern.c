/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#define KBUILD_MODNAME bar_apply

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "custom_types.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"
#include "utils/types.h"

#include "bar_maps.h"
#include "tail_call_dispatcher.h"
#include "stats_maps.h"
#include "stats_types.h"

/* ========================================================================== */
/*                     DDN NOTIFICATION (TS 23.502 §4.2.3.3)                  */
/* ========================================================================== */

/**
 * @brief Submit a Downlink Data Notification event to userspace
 *
 * Triggers the Network-Triggered Service Request procedure
 * (TS 23.502 §4.2.3.3): userspace sends PFCP Session Report
 * to SMF, SMF sends N1N2 message to AMF, AMF pages the UE.
 *
 * @param seid PFCP session ID
 * @param cfg BAR configuration
 * @param pctx Packet context (for pdr_id, ue_ip)
 * @param now_ns Current timestamp
 * @return true iff the record was reserved and submitted to the ring buffer;
 *         false when the ring is full. Nothing was produced then, so the
 *         caller must not commit the notification latch.
 */
static __always_inline bool bar_submit_ddn(
    __u64 seid, struct bar_config* cfg, struct packet_context* pctx,
    __u64 now_ns) {
  struct bar_ddn_event* evt =
      bpf_ringbuf_reserve(&bar_ddn_ringbuf_map, sizeof(*evt), 0);

  if (!evt) {
    bpf_debug(
        "BAR: Ringbuf full — DDN dropped "
        "SEID=%llu",
        seid);
    return false;
  }

  evt->seid         = seid;
  evt->bar_id       = cfg->bar_id;
  evt->pdr_id       = pctx->pdr_id;
  evt->timestamp_ns = now_ns;
  evt->ue_ip        = pctx->ue_ip;
  evt->pad          = 0;

  /* bpf_ringbuf_submit() returns void and cannot fail once the reservation
   * succeeded, so a successful reserve() is the whole success test. */
  bpf_ringbuf_submit(evt, 0);

  bpf_debug(
      "BAR: DDN submitted  — "
      "BAR-ID = %u, SEID = %llu, UE-IP = %pI4",
      cfg->bar_id, seid, &pctx->ue_ip);

  return true;
}

/**
 * @brief Send a DDN (Downlink Data Notification) if one is due. This is the
 *        only place a DDN is produced.
 *
 *   1. No DDN if no FAR asked to notify the CP (NOCP, §8.2.26).
 *   2. A DDN is due if the notification latch is clear, or if a non-zero
 *      Downlink Data Notification Delay (§8.2.28) has passed since the
 *      last DDN.
 *   3. A compare-and-swap to NOTIFY_CLAIMED lets exactly one CPU send it.
 *   4. On success the send time is stored. If the ring is full, the old
 *      value is restored so that the next packet tries again.
 *
 * The delay is used as a repeat gap, not as a delay before the first DDN
 * (see bar_config.dl_notification_delay_50ms).
 *
 * @param seid   PFCP session ID
 * @param cfg    BAR configuration (map value)
 * @param state  Per-session BAR runtime state (map value)
 * @param pctx   Packet context (for pdr_id, ue_ip)
 * @param now_ns Current timestamp
 */
static __always_inline void bar_notify_if_due(
    __u64 seid, struct bar_config* cfg, struct bar_state* state,
    struct packet_context* pctx, __u64 now_ns) {
  /* (1) NOCP gate — BUFF without NOCP buffers silently (§8.2.26). */
  if (!cfg->notify_cp) {
    bpf_debug(
        "BAR: notify_cp=0 for SEID=%llu — "
        "buffering silently, no DDN (§8.2.26)",
        seid);
    return;
  }

  /* (2) Is a DDN due? Remember the value the compare-and-swap must replace. */
  __u64 last_ddn = state->last_ddn_ns;
  __u64 expected;

  if (last_ddn == NOTIFY_FREE) {
    /* Notification latch clear: no DDN since the entry was created or last
     * re-armed. */
    expected = NOTIFY_FREE;
  } else if (
      (last_ddn & NOTIFY_CLAIMED) == 0 &&
      cfg->dl_notification_delay_50ms != 0 &&
      (now_ns - last_ddn) >=
          (__u64) cfg->dl_notification_delay_50ms * 50000000ULL) {
    /* A DDN was sent, none is in flight, and the non-zero delay has passed
     * since it (§8.2.28: the IE is in 50 ms units, 1 unit = 50 000 000 ns):
     * send a repeat DDN. */
    expected = last_ddn;
  } else {
    bpf_debug(
        "BAR: DDN suppressed for SEID=%llu — "
        "already delivered or in flight (§8.2.28)",
        seid);
    return;
  }

  /* (3) Only the CPU whose compare-and-swap succeeds submits the DDN event. */
  if (__sync_val_compare_and_swap(
          &state->last_ddn_ns, expected, NOTIFY_CLAIMED) != expected) {
    bpf_debug(
        "BAR: DDN not sent for SEID=%llu — "
        "notification latch changed meanwhile",
        seid);
    return;
  }

  /* While the submit is in flight, last_ddn_ns holds NOTIFY_CLAIMED, not a
   * send time, so notification_sent, which mirrors the latch for bpftool
   * readers only, reads 0. */
  state->notification_sent = 0;

  /* (4) Store the send time only if the submit succeeded; otherwise restore
   * the previous value, so that the next DL packet tries again. */
  if (bar_submit_ddn(seid, cfg, pctx, now_ns)) {
    /* Bit 63 is kept clear so that a send time never equals NOTIFY_CLAIMED. */
    state->last_ddn_ns       = now_ns & ~NOTIFY_CLAIMED;
    state->notification_sent = 1;
    return;
  }

  state->last_ddn_ns       = expected;
  state->notification_sent = (expected == NOTIFY_FREE) ? 0 : 1;

  bpf_debug(
      "BAR: notification latch restored for SEID=%llu — "
      "ring full, next DL packet retries",
      seid);
  return;
}

/* ========================================================================== */
/*                         BAR APPLICATION                                    */
/* ========================================================================== */

SEC("xdp")
int bar_apply(struct xdp_md* ctx) {
  bpf_debug("=====< BAR Apply >====");

  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("Error: Failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  u64 seid = pctx->seid;

  /* ---------------------------------------------------------------- */
  /*  Step 1: Look up the BAR configuration                           */
  /*  (Create BAR, Table 7.5.2.6-1)                                   */
  /* ---------------------------------------------------------------- */
  struct bar_config* cfg = bpf_map_lookup_elem(&bar_config_map, &seid);

  if (!cfg) {
    /*
     * FAR said BUFFER but there is no bar_config for the session — cannot
     * buffer. Drop the packet. The control plane writes one for every BUFF
     * FAR (Setup, or SetupWithoutBar for a BAR-less one), so this is reached
     * only before that has run, e.g. for BUFF in the Establishment Request.
     */
    bpf_debug(
        "BAR: No BAR config for SEID=%llu — "
        "cannot buffer, dropping",
        seid);
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  bpf_debug(
      "BAR: BAR-ID=%u, buf_pkt_cnt=%u, ddn_delay=%u x50ms", cfg->bar_id,
      cfg->suggested_buf_pkt_cnt, cfg->dl_notification_delay_50ms);

  /* ---------------------------------------------------------------- */
  /*  Step 2: Lookup or initialize buffering state                    */
  /* ---------------------------------------------------------------- */
  struct bar_state* state = bpf_map_lookup_elem(&bar_state_map, &seid);

  if (!state) {
    /*
     * No state entry — the control plane should have pre-created it
     * (BARProgram::InitBarStateMap). Create a zeroed entry here: without one
     * there is no notification latch, and every DL packet would send its own
     * DDN. BPF_NOEXIST keeps an entry that another CPU created meanwhile, and
     * its notification latch, intact.
     */
    struct bar_state fresh = {};

    bpf_map_update_elem(&bar_state_map, &seid, &fresh, BPF_NOEXIST);
    state = bpf_map_lookup_elem(&bar_state_map, &seid);

    if (!state) {
      /*
       * Fail closed: without a state entry there is no notification latch;
       * drop and count under XDP_ABORTED (mc_stats_map).
       */
      bpf_debug(
          "BAR: Cannot establish state for SEID=%llu — "
          "failing closed (no DDN, packet dropped)",
          seid);
      return xdp_stats_record_action(ctx, XDP_ABORTED);
    }

    bpf_debug(
        "BAR: State entry created on the fly for SEID=%llu "
        "(control plane had not pre-created it)",
        seid);
  }

  __u64 now_ns = bpf_ktime_get_ns();

  /* ---------------------------------------------------------------- */
  /*  Step 3: DDN, if due (NOCP gate and notification latch, §8.2.28) */
  /* ---------------------------------------------------------------- */
  bar_notify_if_due(seid, cfg, state, pctx, now_ns);

  /* ---------------------------------------------------------------- */
  /*  Step 4: Buffer limit                                            */
  /*  (Suggested Buffering Packets Count, §8.2.100)                   */
  /* ---------------------------------------------------------------- */
  if (cfg->suggested_buf_pkt_cnt > 0) {
    /*
     * Concurrent CPUs can each read a count below the limit, so up to
     * (number of CPUs − 1) packets beyond the Suggested Buffering Packets Count
     * can pass this check, although TS 29.244 Table 7.5.2.6-1 says that excess
     * packets shall be discarded.
     */
    __u32 current_count = state->buffered_pkt_count;
    __sync_fetch_and_add(&state->buffered_pkt_count, 1);

    if (current_count >= cfg->suggested_buf_pkt_cnt) {
      /* Over the limit: drop. */
      bpf_debug(
          "BAR: Buffer full (%u >= %u) SEID=%llu — "
          "dropping excess",
          current_count, cfg->suggested_buf_pkt_cnt, seid);
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    bpf_debug(
        "BAR: Buffering packet %u/%u for SEID=%llu", current_count + 1,
        cfg->suggested_buf_pkt_cnt, seid);
  } else {
    /* No limit configured: count anyway, for bpftool inspection. */
    __sync_fetch_and_add(&state->buffered_pkt_count, 1);

    bpf_debug(
        "BAR: Buffering packet for SEID=%llu "
        "(no limit configured)",
        seid);
  }

  /* ---------------------------------------------------------------- */
  /*  Step 5: Terminal action — hand the packet to userspace          */
  /* ---------------------------------------------------------------- */
  /*
   * Redirect the packet (still Ethernet + IPv4) to the AF_XDP socket of its
   * RX queue. Userspace holds it until the SMF ends buffering, then sends it
   * on the new rules.
   *
   * With no socket in the slot the packet is dropped. Do not use XDP_PASS as
   * the fallback: the host stack would get a packet meant for the UE.
   *
   * BAR is a terminal node — no further tail calls.
   */
  bpf_debug(
      "BAR: redirect to the AF_XDP socket of RX queue %u, SEID=%llu",
      ctx->rx_queue_index, seid);
  return xdp_stats_record_action(
      ctx, bpf_redirect_map(&xskmap, ctx->rx_queue_index, XDP_DROP));
}

char _license[] SEC("license") = "GPL";
