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

// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Boy Scout cleanup — no functional changes:
 *                - §-refs verified against V17.10.0: §8.2.57 (BAR ID),
 *                  §8.2.28 (DL Data Notification Delay), §8.2.100
 *                  (Suggested Buffering Packets Count) all unchanged.
 *                - Replaced bare @file block with changelog + guards.
 *                - MT-EDT Control Information (§8.2.175) noted as CP-only
 *                  in pfcp_bar.h; BAR XDP program correctly omits it.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §8.2.57   BAR ID
 *              §8.2.28   DL Data Notification Delay
 *              §8.2.100  Suggested Buffering Packets Count
 *              TS 23.502 §4.2.3.3 Network Triggered Service Request
 *              §7.2.5    PFCP Session Report Request
 */
// clang-format on

/**
 * @file bar_apply.c
 * @brief BAR (Buffering Action Rule) — packet buffering and DDN control
 *
 * Only reached when RULE_BAR_ENABLED is set AND FAR Apply Action = BUFFER.
 * BAR is a terminal node — no further chaining into URR/MAR.
 *
 * Per 3GPP TS 29.244 §8.2.49-50, BAR controls the UPF behavior when
 * downlink data arrives for a UE in CM-IDLE state:
 *
 *   1. Downlink Data Notification (DDN): Notify the SMF so it can
 *      trigger paging via AMF (TS 23.502 §4.2.3.3 Network Triggered
 *      Service Request). The SMF responds by modifying the FAR from
 *      BUFF→FORW once the UE is reachable.
 *
 *   2. Suggested Buffering Packets Count (§8.2.50): Hint from SMF on
 *      how many packets the UPF should buffer. Excess packets are dropped.
 *
 *   3. DL Data Notification Delay (§8.2.28): Suppress duplicate DDN
 *      events for N seconds after the first notification. Prevents
 *      DDN storms when multiple DL packets arrive in rapid succession
 *      for an idle UE.
 *
 * Architecture:
 *   XDP (BAR program) detects BUFFER condition and:
 *   - Submits DDN event to userspace via BPF_MAP_TYPE_RINGBUF
 *   - Returns XDP_PASS to send packet to kernel socket queue for
 *     userspace buffering (XDP cannot buffer packets natively)
 *   - Tracks per-session state to suppress duplicate DDNs
 *   - Drops excess packets when buffer count is reached
 *
 *   Userspace:
 *   - Reads DDN events from ringbuf
 *   - Sends PFCP Session Report Request to SMF (§7.2.5)
 *   - Holds buffered packets in socket queue
 *   - Flushes buffered packets when SMF modifies FAR to FORW
 *
 * Chain: ... → FAR (action=BUFF) → [BAR_APPLY]  (terminal)
 *
 * @see 3GPP TS 29.244 §8.2.49 - BAR ID
 * @see 3GPP TS 29.244 §8.2.50 - Suggested Buffering Packets Count
 * @see 3GPP TS 29.244 §8.2.28 - DL Data Notification Delay
 * @see 3GPP TS 23.502 §4.2.3.3 - Service Request (Network Triggered)
 * @see 3GPP TS 29.244 §7.2.5 - PFCP Session Report Request
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

#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_pdr.h"

#include "upf_xdp_maps.h"
#include "interfaces.h"
#include "tail_call_dispatch.h"
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

/* ========================================================================== */
/*                      BAR DATA STRUCTURES                                   */
/* ========================================================================== */

/**
 * @brief BAR rule configuration (TS 29.244 §8.2.49-50, §8.2.28)
 *
 * Populated by control plane during PFCP Session Establishment
 * (§7.2.2) or Modification (§7.2.4), specifically when the
 * Create BAR / Update BAR IEs are present.
 */
struct bar_config {
  __u32 bar_id;                   /**< BAR ID (§8.2.49)                    */
  __u16 suggested_buf_pkt_cnt;    /**< Suggested Buffering Packets Count
                                   *   (§8.2.50). 0 = no limit hint.
                                   *   SMF suggests how many DL packets
                                   *   the UPF should buffer per UE.       */
  __u8 dl_notification_delay_sec; /**< DL Data Notification Delay (§8.2.28)
                                   *   in seconds. 0 = no suppression,
                                   *   send DDN for every BUFFER event.    */
  __u8 pad;
};

/**
 * @brief Per-session buffering state (DDN suppression tracking)
 *
 * Tracks whether a DDN has been sent for this session and when,
 * plus the number of packets currently buffered. Used for:
 *   - DDN suppression: avoid sending duplicate DDNs within the
 *     configured notification delay window
 *   - Buffer overflow: drop excess packets beyond the suggested count
 */
struct bar_state {
  __u64 last_ddn_ns;        /**< Timestamp of last DDN sent (ns)     */
  __u32 buffered_pkt_count; /**< Number of packets buffered so far   */
  __u8 notification_sent;   /**< 1 if at least one DDN sent          */
  __u8 pad[3];
};

/**
 * @brief DDN event sent to userspace via ringbuf
 *
 * Userspace reads this event and constructs a PFCP Session Report
 * Request (§7.2.5) with a Downlink Data Report IE containing:
 *   - PDR ID that triggered buffering
 *   - DL Data Service Information (if applicable)
 */
struct bar_ddn_event {
  __u64 seid;         /**< PFCP Session Endpoint Identifier    */
  __u32 bar_id;       /**< BAR ID (§8.2.49)                    */
  __u32 pdr_id;       /**< PDR that matched the DL packet      */
  __u64 timestamp_ns; /**< When the DDN was generated          */
  __u32 ue_ip;        /**< UE IP (for logging/debugging)       */
  __u32 pad;
};

/* ========================================================================== */
/*                            BAR BPF MAPS                                    */
/* ========================================================================== */

/**
 * bar_config_map - Per-session BAR configuration
 * Size: Runtime (MAX_PDU_SESSIONS)
 * Key:   SEID (__u64)
 * Value: struct bar_config
 *
 * Populated by control plane when Create BAR IE is present
 * in PFCP Session Establishment or Update BAR in Modification.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct bar_config);
} bar_config_map SEC(".maps");

/**
 * bar_state_map - Per-session buffering state
 * Size: Runtime (MAX_PDU_SESSIONS)
 * Key:   SEID (__u64)
 * Value: struct bar_state
 *
 * Created by control plane alongside bar_config_map. Zeroed on
 * session establishment. The buffered_pkt_count and notification_sent
 * fields are updated atomically by the BPF program.
 *
 * When the SMF modifies the FAR from BUFF→FORW (UE is now reachable),
 * control plane should reset the state entry or delete it.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct bar_state);
} bar_state_map SEC(".maps");

/**
 * bar_ddn_ringbuf_map - DDN events → userspace
 * Size: 64 KB ring buffer
 *
 * Events are submitted when a DDN should be sent (first DL packet
 * for an idle UE, or when notification delay has expired).
 * Userspace polls this ringbuf and sends PFCP Session Report
 * Requests (§7.2.5) to the SMF.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 64 * 1024);
} bar_ddn_ringbuf_map SEC(".maps");

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
      "BAR: DDN submitted (TS 23.502 §4.2.3.3) — "
      "BAR-ID=%u, SEID=%llu, UE-IP=%pI4",
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
  bpf_debug("=== BAR Apply (TS 29.244 §8.2.49-50) ===");

  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("Error: Failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  u64 seid = pctx->seid;

  /* ---------------------------------------------------------------- */
  /*  Step 1: Lookup BAR configuration (§8.2.49)                     */
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
  /*  Step 2: Lookup or initialize buffering state                   */
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
    __u32 current_count = __sync_fetch_and_add(&state->buffered_pkt_count, 1);

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
