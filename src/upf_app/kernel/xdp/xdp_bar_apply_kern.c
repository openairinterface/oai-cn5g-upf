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
 * @return true iff the record was reserved AND submitted to the ring buffer;
 *         false when the ring is full (nothing was produced, so the caller
 *         must NOT commit the notification latch).
 */
static __always_inline bool bar_submit_ddn(
    __u64 seid, struct bar_config* cfg, struct packet_context* pctx,
    __u64 now_ns) {
  struct bar_ddn_event* evt =
      bpf_ringbuf_reserve(&bar_ddn_ringbuf_map, sizeof(*evt), 0);

  if (!evt) {
    bpf_debug(
        "BAR: Ringbuf full — DDN dropped "
        "SEID=%llu (§7.2.5)",
        seid);
    return false;
  }

  evt->seid         = seid;
  evt->bar_id       = cfg->bar_id;
  evt->pdr_id       = pctx->pdr_id;
  evt->timestamp_ns = now_ns;
  evt->ue_ip        = pctx->ue_ip;
  evt->pad          = 0;

  /* bpf_ringbuf_submit() is void and cannot fail once the reservation
   * succeeded — reserve() + submit() is therefore the whole success test. */
  bpf_ringbuf_submit(evt, 0);

  bpf_debug(
      "BAR: DDN submitted  — "
      "BAR-ID = %u, SEID = %llu, UE-IP = %pI4",
      cfg->bar_id, seid, &pctx->ue_ip);

  return true;
}

/**
 * @brief DDN delivery state machine — single-winner 64-bit atomic claim.
 *
 * This is the ONLY place a DDN is produced. It replaces the old
 * "bar_should_notify() then submit then unconditionally latch" pair, whose
 * control gate was the derived @c notification_sent byte: @c notify_epoch_ns
 * is now the single source of truth and @c notification_sent is only its
 * readback mirror (bar_types.h).
 *
 * Protocol (per notification window — the first DDN of an idle burst AND
 * every reopened DL-Data-Notification-Delay window):
 *   1. NOCP gate (§8.2.26 bit 3): @c cfg->notify_cp == 0 means the FAR(s)
 *      referencing this BAR did not ask the CP to be notified — buffer
 *      silently, never produce a DDN.
 *   2. Pick the expected value @p from of the claim word:
 *        NOTIFY_FREE            -> first DDN of the idle burst;
 *        a committed epoch      -> only if a delay is configured and the
 *                                  window has expired (§8.2.28, 50 ms units);
 *        NOTIFY_CLAIMED / other -> suppress (delivered already, or a submit
 *                                  is in flight on another CPU).
 *   3. 64-bit __sync_val_compare_and_swap(from -> NOTIFY_CLAIMED). Exactly
 *      one CPU can win a given @p from value, so concurrent DL packets on any
 *      number of CPUs cannot both submit for the same window. The operand is
 *      the naturally 8-byte-aligned @c notify_epoch_ns at offset 0 of the map
 *      value (an 8/32-bit __sync_* does not compile for the BPF target).
 *   4. Commit @c now_ns (high bit cleared, so a committed epoch can never be
 *      mistaken for NOTIFY_CLAIMED) ONLY on a successful submit; on a full
 *      ring restore @p from so the next DL packet retries — a transient ring
 *      overflow delays a DDN, it never permanently suppresses it.
 *
 * The claim owner is the only writer of the word between the CAS and the
 * final store (every other CPU's CAS fails against NOTIFY_CLAIMED), so the
 * commit/restore store and the mirror update need no further atomicity.
 *
 * @param seid   PFCP session ID
 * @param cfg    BAR configuration (map value)
 * @param state  Per-session BAR runtime state (map value)
 * @param pctx   Packet context (for pdr_id, ue_ip)
 * @param now_ns Current timestamp
 * @return true iff this packet produced a DDN
 */
static __always_inline bool bar_notify_if_due(
    __u64 seid, struct bar_config* cfg, struct bar_state* state,
    struct packet_context* pctx, __u64 now_ns) {
  /* (1) NOCP gate — BUFF without NOCP buffers silently (§8.2.26). */
  if (!cfg->notify_cp) {
    bpf_debug(
        "BAR: notify_cp=0 for SEID=%llu — "
        "buffering silently, no DDN (§8.2.26)",
        seid);
    return false;
  }

  /* (2) Which value of the claim word are we allowed to take over? */
  __u64 cur = state->notify_epoch_ns;
  __u64 from;

  if (cur == NOTIFY_FREE) {
    /* First DDN of the idle burst. */
    from = NOTIFY_FREE;
  } else if (
      (cur & NOTIFY_CLAIMED) == 0 && cfg->dl_notification_delay_50ms != 0 &&
      (now_ns - cur) >= (__u64) cfg->dl_notification_delay_50ms * 50000000ULL) {
    /* Committed epoch, no submit in flight, delay window expired (§8.2.28:
     * the IE is in 50 ms units, 1 unit = 50 000 000 ns) — re-notify. */
    from = cur;
  } else {
    bpf_debug(
        "BAR: DDN suppressed for SEID=%llu — "
        "already delivered or in flight (§8.2.28)",
        seid);
    return false;
  }

  /* (3) Single-winner claim. */
  if (__sync_val_compare_and_swap(
          &state->notify_epoch_ns, from, NOTIFY_CLAIMED) != from) {
    bpf_debug(
        "BAR: DDN claim lost for SEID=%llu — "
        "another CPU owns this notification window",
        seid);
    return false;
  }

  /* The word now reads NOTIFY_CLAIMED, which is not a committed epoch, so the
   * derived mirror must read 0 for as long as the submit is in flight. */
  state->notification_sent = 0;

  /* (4) Commit only on a successful submit, otherwise release the claim. */
  if (bar_submit_ddn(seid, cfg, pctx, now_ns)) {
    state->notify_epoch_ns   = now_ns & ~NOTIFY_CLAIMED;
    state->notification_sent = 1; /* derived mirror */
    return true;
  }

  state->notify_epoch_ns   = from;
  state->notification_sent = (from == NOTIFY_FREE) ? 0 : 1; /* derived mirror */

  bpf_debug(
      "BAR: DDN claim released for SEID=%llu — "
      "ring full, next DL packet retries (§7.2.5)",
      seid);
  return false;
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
  /*  Step 1: Lookup BAR configuration (§8.2.49)                      */
  /* ---------------------------------------------------------------- */
  struct bar_config* cfg = bpf_map_lookup_elem(&bar_config_map, &seid);

  if (!cfg) {
    /*
     * FAR said BUFFER but no BAR configured — cannot buffer.
     * Drop packet. Control plane should always create BAR when
     * creating a FAR with BUFF action.
     */
    bpf_debug(
        "BAR: No BAR config for SEID=%llu — "
        "cannot buffer, dropping (§8.2.49)",
        seid);
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  bpf_debug(
      "BAR: BAR-ID=%u, buf_pkt_cnt=%u, ddn_delay=%u x50ms "
      "(§8.2.49, §8.2.50, §8.2.28)",
      cfg->bar_id, cfg->suggested_buf_pkt_cnt, cfg->dl_notification_delay_50ms);

  /* ---------------------------------------------------------------- */
  /*  Step 2: Lookup or initialize buffering state                    */
  /* ---------------------------------------------------------------- */
  struct bar_state* state = bpf_map_lookup_elem(&bar_state_map, &seid);

  if (!state) {
    /*
     * No state entry — the control plane should have pre-created it
     * (BARProgram::InitBarStateMap). Create a zeroed entry here rather than
     * emitting an unlatched DDN per packet: without a state entry the claim
     * word does not exist, so every DL packet of the burst would report.
     * BPF_NOEXIST keeps a racing CPU's entry (and any live latch) intact.
     */
    struct bar_state fresh = {};

    bpf_map_update_elem(&bar_state_map, &seid, &fresh, BPF_NOEXIST);
    state = bpf_map_lookup_elem(&bar_state_map, &seid);

    if (!state) {
      /*
       * FAIL CLOSED: state could not be established (bar_state_map full or
       * the update was rejected). Drop and count the packet under
       * XDP_ABORTED in mc_stats_map so userspace can reconcile the session
       * — never fall back to an unlatched per-packet DDN.
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
  /*  Step 3: DDN notification — NOCP gate + atomic claim (§8.2.28)  */
  /* ---------------------------------------------------------------- */
  /*
   * Both the normal path and the missing-state path above reach this single
   * call, so the NOCP gate and the one-shot latch apply identically to both.
   */
  bar_notify_if_due(seid, cfg, state, pctx, now_ns);

  /* ---------------------------------------------------------------- */
  /*  Step 4: Buffer overflow check (§8.2.50)                        */
  /* ---------------------------------------------------------------- */
  if (cfg->suggested_buf_pkt_cnt > 0) {
    __u32 current_count = state->buffered_pkt_count;      // plain read
    __sync_fetch_and_add(&state->buffered_pkt_count, 1);  // atomic increment

    if (current_count >= cfg->suggested_buf_pkt_cnt) {
      /*
       * Buffer full — drop excess packets. The suggested count
       * is a hint from SMF (§8.2.50); exceeding it means the UE
       * has not responded to paging yet.
       */
      bpf_debug(
          "BAR: Buffer full (%u >= %u) SEID=%llu — "
          "dropping excess (§8.2.50)",
          current_count, cfg->suggested_buf_pkt_cnt, seid);
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    bpf_debug(
        "BAR: Buffering packet %u/%u for SEID=%llu (§8.2.50)",
        current_count + 1, cfg->suggested_buf_pkt_cnt, seid);
  } else {
    /* No buffer limit configured — count anyway for stats */
    __sync_fetch_and_add(&state->buffered_pkt_count, 1);

    bpf_debug(
        "BAR: Buffering packet for SEID=%llu "
        "(no limit configured)",
        seid);
  }

  /* ---------------------------------------------------------------- */
  /*  Step 5: Terminal action — Phase 1 drops the buffered packet    */
  /* ---------------------------------------------------------------- */
  /*
   * Phase 1 is notify-only: there is NO buffer-capture path yet, so the DL
   * packet is intentionally dropped once it has been counted and (if due)
   * has produced a DDN. XDP_PASS must NOT be used here — it would inject a
   * subscriber-bound packet into the host network stack, where it could be
   * locally consumed or forwarded (data leak / operational hazard).
   *
   * Phase 2 replaces this XDP_DROP with an XDP_REDIRECT into an
   * AF_XDP socket, so userspace can hold the packet until the SMF modifies
   * the FAR from BUFF→FORW (TS 29.244 §7.2.4) — i.e. until the UE has moved
   * from CM-IDLE to CM-CONNECTED — and then flush it.
   *
   * When the FAR is modified, the control plane should:
   *   1. Update FAR action from BUFF to FORW
   *   2. Reset bar_state (notify_epoch_ns=NOTIFY_FREE, buffered_pkt_count=0,
   *      notification_sent=0)
   *   3. Flush any buffered packets through the new forwarding path
   *
   * BAR is a terminal node — no further tail calls.
   */
  bpf_debug(
      "BAR: XDP_DROP — Phase 1 notify-only, no capture "
      "path, SEID=%llu",
      seid);
  return xdp_stats_record_action(ctx, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
