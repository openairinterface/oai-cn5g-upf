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

#include "linux/custom_types.h"
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
 */
static __always_inline void bar_submit_ddn(
    __u64 seid, struct bar_config* cfg, struct packet_context* pctx,
    __u64 now_ns) {
  struct bar_ddn_event* evt =
      bpf_ringbuf_reserve(&bar_ddn_ringbuf_map, sizeof(*evt), 0);

  if (!evt) {
    bpf_debug(
        "BAR: Ringbuf full — DDN dropped "
        "SEID=%llu (§7.2.5)",
        seid);
    return;
  }

  evt->seid         = seid;
  evt->bar_id       = cfg->bar_id;
  evt->pdr_id       = pctx->pdr_id;
  evt->timestamp_ns = now_ns;
  evt->ue_ip        = pctx->ue_ip;
  evt->pad          = 0;

  bpf_ringbuf_submit(evt, 0);

  bpf_debug(
      "BAR: DDN submitted  — "
      "BAR-ID = %u, SEID = %llu, UE-IP = %pI4",
      cfg->bar_id, seid, &pctx->ue_ip);
}

/**
 * @brief Check if DDN should be sent or suppressed
 *
 * DDN suppression logic (DL Data Notification Delay, §8.2.28):
 *   - First packet for an idle session: always send DDN
 *   - Subsequent packets within delay window: suppress DDN
 *   - After delay expires: send new DDN
 *
 * @param state Per-session buffering state
 * @param delay_sec Configured notification delay (0 = no suppression)
 * @param now_ns Current timestamp
 * @return true if DDN should be sent, false if suppressed
 */
static __always_inline bool bar_should_notify(
    struct bar_state* state, __u8 delay_sec, __u64 now_ns) {
  /* First packet ever for this idle session — always notify */
  if (!state->notification_sent) return true;

  /* No delay configured — notify on every BUFFER event */
  if (delay_sec == 0) return true;

  /* Check if delay has expired since last DDN */
  __u64 delay_ns = (__u64) delay_sec * 1000000000ULL;
  __u64 elapsed  = now_ns - state->last_ddn_ns;

  if (elapsed >= delay_ns) return true;

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
      "BAR: BAR-ID=%u, buf_pkt_cnt=%u, ddn_delay=%u sec "
      "(§8.2.49, §8.2.50, §8.2.28)",
      cfg->bar_id, cfg->suggested_buf_pkt_cnt, cfg->dl_notification_delay_sec);

  /* ---------------------------------------------------------------- */
  /*  Step 2: Lookup or initialize buffering state                    */
  /* ---------------------------------------------------------------- */
  struct bar_state* state = bpf_map_lookup_elem(&bar_state_map, &seid);

  if (!state) {
    /*
     * No state entry — control plane should pre-create it.
     * As fallback, send DDN and drop the packet (cannot track
     * buffering state without a map entry).
     */
    bpf_debug(
        "BAR: No state entry for SEID=%llu — "
        "sending DDN, dropping packet",
        seid);

    __u64 now_ns = bpf_ktime_get_ns();

    bar_submit_ddn(seid, cfg, pctx, now_ns);
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  __u64 now_ns = bpf_ktime_get_ns();

  /* ---------------------------------------------------------------- */
  /*  Step 3: DDN notification with suppression (§8.2.28)            */
  /* ---------------------------------------------------------------- */
  if (bar_should_notify(state, cfg->dl_notification_delay_sec, now_ns)) {
    bar_submit_ddn(seid, cfg, pctx, now_ns);

    /*
     * Update DDN state. These writes are racy across CPUs but
     * the consequence is at most one extra DDN — acceptable.
     */
    state->last_ddn_ns       = now_ns;
    state->notification_sent = 1;

    bpf_debug("BAR: DDN sent for SEID=%llu (§8.2.28)", seid);
  } else {
    bpf_debug(
        "BAR: DDN suppressed for SEID=%llu — "
        "within delay window (§8.2.28)",
        seid);
  }

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
  /*  Step 5: Pass packet to kernel for userspace buffering          */
  /* ---------------------------------------------------------------- */
  /*
   * XDP_PASS sends the packet to the kernel network stack. Userspace
   * captures it via a raw socket or AF_XDP and holds it until the SMF
   * modifies the FAR from BUFF→FORW (TS 29.244 §7.2.4), indicating
   * the UE has transitioned from CM-IDLE to CM-CONNECTED state.
   *
   * When FAR is modified, control plane should:
   *   1. Update FAR action from BUFF to FORW
   *   2. Reset bar_state (buffered_pkt_count=0, notification_sent=0)
   *   3. Flush any buffered packets through the new forwarding path
   *
   * BAR is a terminal node — no further tail calls.
   */
  bpf_debug(
      "BAR: XDP_PASS — packet sent to kernel for "
      "buffering, SEID=%llu",
      seid);
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
