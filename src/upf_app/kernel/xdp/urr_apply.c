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
 * Changes:     V17.10.0 integration — two new active URR fields:
 *                - time_quota (§8.2.47): maximum allowed session duration for
 *                  time-based quota enforcement.  When elapsed time since
 *                  monitoring_time_ns ≥ time_quota_ns the packet is dropped
 *                  and a URR_TRIGGER_TIMQU Usage Report is submitted.
 *                - dropped_dl_traffic_threshold (§8.2.49): reports when
 *                  dropped DL bytes or packets exceed the configured threshold.
 *                  The XDP program counts DL drops via a separate atomic
 *                  counter in urr_volume and fires URR_TRIGGER_DROTH.
 *              urr_config struct extended:
 *                - time_quota_ns   (new) — §8.2.47
 *                - dropped_dl_threshold_bytes  (new) — §8.2.49
 *                - dropped_dl_threshold_pkts   (new) — §8.2.49
 *              urr_volume struct extended:
 *                - dropped_dl_bytes   (new counter)
 *                - dropped_dl_packets (new counter)
 *              Boy Scout cleanup:
 *                - Replaced bare @file block with changelog + guards.
 * ⚠️  urr_config ABI change — update ConvertUrr() in urr_xdp_user.cpp
 *     and re-pin the map before loading.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §8.2.47   Time Quota (new field)
 *              §8.2.49   Dropped DL Traffic Threshold (new field)
 *              §8.2.53   Reporting Triggers    §8.2.54  URR ID
 *              §8.2.72   Measurement Period    §7.2.5   Session Report Request
 */
// clang-format on

/**
 * @file urr_apply.c
 * @brief URR (Usage Reporting Rule) — volume and time measurement
 *
 * Only reached when RULE_URR_ENABLED is set in pctx->rules_enabled.
 *
 * Per 3GPP TS 29.244 §8.2.44-48, URR measures:
 *   - Volume Measurement (§8.2.45): UL/DL/total bytes and packets
 *   - Duration Measurement (§8.2.47): Session duration
 *   - Volume Threshold (§8.2.48): Report when threshold crossed
 *   - Volume Quota (§8.2.46): DROP when quota exhausted
 *   - Reporting Triggers (§8.2.53): Conditions to generate reports
 *
 * Implementation notes:
 *   - Volume counters use a non-PERCPU HASH with __sync_fetch_and_add()
 *     for cross-CPU atomic updates. This allows threshold checking
 *     directly in BPF without userspace aggregation.
 *   - Threshold/quota config maps are populated by control plane during
 *     PFCP Session Establishment (§7.2.2) / Modification (§7.2.4).
 *   - When Volume Quota is exhausted, final_action is overridden to
 *     FINAL_ACTION_DROP — the packet is dropped.
 *   - Usage Report events are submitted to userspace via
 *     BPF_MAP_TYPE_RINGBUF, which reads them and constructs
 *     PFCP Session Report Requests (§7.2.5).
 *
 * Chain: ... → [QER] → [URR_APPLY] → [MAR] → execute
 *
 * @see 3GPP TS 29.244 §8.2.44 - URR ID
 * @see 3GPP TS 29.244 §8.2.45 - Volume Measurement
 * @see 3GPP TS 29.244 §8.2.46 - Volume Quota
 * @see 3GPP TS 29.244 §8.2.47 - Duration Measurement
 * @see 3GPP TS 29.244 §8.2.48 - Volume/Time Threshold
 * @see 3GPP TS 29.244 §8.2.53 - Reporting Triggers
 * @see 3GPP TS 29.244 §8.2.72 - Measurement Period
 * @see 3GPP TS 29.244 §7.2.5 - PFCP Session Report Request
 */

#define KBUILD_MODNAME urr_apply

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
/*                      URR DATA STRUCTURES                                   */
/* ========================================================================== */

/**
 * @brief Volume Measurement counters (TS 29.244 §8.2.45)
 *
 * Tracks UL/DL/total bytes and packets for a PFCP session.
 * Updated atomically via __sync_fetch_and_add() since multiple
 * CPUs may process packets for the same session concurrently.
 *
 * The fields mirror the Volume Measurement IE encoding:
 *   - TOVOL (bit 0): Total Volume present
 *   - ULVOL (bit 1): Uplink Volume present
 *   - DLVOL (bit 2): Downlink Volume present
 */
struct urr_volume {
  __u64 ul_bytes;      /**< Uplink byte count                       */
  __u64 dl_bytes;      /**< Downlink byte count                     */
  __u64 ul_packets;    /**< Uplink packet count                     */
  __u64 dl_packets;    /**< Downlink packet count                   */
  __u64 total_bytes;   /**< Total (UL+DL) byte count                */
  __u64 total_packets; /**< Total (UL+DL) packet count              */
  /*
   * Dropped DL counters — V17.10.0 addition (§8.2.49).
   *
   * Incremented by downstream programs when a DL packet is dropped
   * due to a closed QER gate or BAR buffer overflow, then read here
   * to evaluate the Dropped DL Traffic Threshold trigger.
   * Atomic updates via __sync_fetch_and_add() (BPF_ATOMIC_ADD,
   * requires kernel ≥ 5.12).
   */
  __u64 dropped_dl_bytes;   /**< Dropped DL byte count  (§8.2.49)       */
  __u64 dropped_dl_packets; /**< Dropped DL packet count (§8.2.49)      */
};

/**
 * @brief Reporting Triggers bitmask (TS 29.244 §8.2.53)
 *
 * Controls which events cause a Usage Report to be generated
 * and sent to the SMF via PFCP Session Report (§7.2.5).
 */
#define URR_TRIGGER_VOLTH (1U << 0) /**< Volume Threshold reached    */
#define URR_TRIGGER_VOLQU (1U << 1) /**< Volume Quota exhausted      */
#define URR_TRIGGER_TIMTH (1U << 2) /**< Time Threshold reached      */
#define URR_TRIGGER_TIMQU (1U << 3) /**< Time Quota exhausted        */
#define URR_TRIGGER_PERIO (1U << 4) /**< Periodic reporting          */
#define URR_TRIGGER_START (1U << 5) /**< Start of traffic detection  */
#define URR_TRIGGER_STOPT (1U << 6) /**< Stop of traffic detection   */
#define URR_TRIGGER_DROTH (1U << 7) /**< Dropped DL threshold        */

/**
 * @brief URR configuration — thresholds, quotas, timing
 *
 * Populated by control plane during PFCP Session Establishment
 * (TS 29.244 §7.2.2) or Modification (TS 29.244 §7.2.4).
 *
 * A value of 0 means the corresponding threshold/quota is not active.
 */
struct urr_config {
  __u32 urr_id;            /**< URR ID (§8.2.44)                         */
  __u8 reporting_triggers; /**< Reporting Triggers bitmask (§8.2.53)     */
  __u8 pad[3];

  /* Volume Threshold (§8.2.48) — generate report when crossed           */
  __u64 volume_threshold_total; /**< Total volume threshold (bytes)      */
  __u64 volume_threshold_ul;    /**< UL volume threshold (bytes)         */
  __u64 volume_threshold_dl;    /**< DL volume threshold (bytes)         */

  /* Volume Quota (§8.2.46) — DROP packets when exhausted                */
  __u64 volume_quota_total; /**< Total volume quota (bytes)              */
  __u64 volume_quota_ul;    /**< UL volume quota (bytes)                 */
  __u64 volume_quota_dl;    /**< DL volume quota (bytes)                 */

  /* Time Threshold (§8.2.48) — generate report after duration           */
  __u64 time_threshold_ns; /**< Time threshold (nanoseconds)             */

  /* Time Quota (§8.2.47) — V17.10.0 addition: DROP when exceeded       */
  __u64 time_quota_ns; /**< Max allowed session duration (ns); 0=off */

  /* Dropped DL Traffic Threshold (§8.2.49) — V17.10.0 addition         */
  __u64 dropped_dl_threshold_bytes; /**< Dropped DL byte threshold; 0=off */
  __u32 dropped_dl_threshold_pkts;  /**< Dropped DL pkt threshold; 0=off  */
  __u32 pad2;

  /* Monitoring Time (§8.2.15) — measurement start timestamp             */
  __u64 monitoring_time_ns; /**< Set to bpf_ktime_get_ns() at start      */

  /* Measurement Period (§8.2.72) — periodic reporting interval          */
  __u64 measurement_period_ns; /**< Periodic report interval (ns)        */
  __u64 last_report_ns;        /**< Timestamp of last periodic report    */
};

/**
 * @brief Usage Report event sent to userspace via ringbuf
 *
 * Userspace reads this event and constructs a PFCP Session Report
 * Request (TS 29.244 §7.2.5) containing the Usage Report IE
 * (TS 29.244 §8.2.107).
 */
struct urr_report_event {
  __u64 seid;   /**< PFCP Session Endpoint Identifier    */
  __u32 urr_id; /**< URR ID that triggered the report    */
  __u8 trigger; /**< Which trigger fired (URR_TRIGGER_*) */
  __u8 pad[3];
  struct urr_volume vol; /**< Snapshot of volume counters         */
  __u64 timestamp_ns;    /**< When the report was generated       */
  __u64 start_time_ns;   /**< Measurement start time (§8.2.15)   */
};

/* ========================================================================== */
/*                            URR BPF MAPS                                    */
/* ========================================================================== */

/**
 * urr_volume_counters_map - Per-session volume counters
 * Size: Runtime (MAX_PDU_SESSIONS)
 * Key:   SEID (__u64)
 * Value: struct urr_volume
 *
 * Non-PERCPU HASH: we need cross-CPU totals for threshold checking.
 * Updated atomically via __sync_fetch_and_add(). This is safe because
 * XDP runs under softirq and __sync builtins compile to BPF_ATOMIC_ADD
 * (requires kernel >= 5.12 for BPF atomic support).
 *
 * Zeroed by control plane on session establishment. Userspace may read
 * counters at any time for reporting without resetting them.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct urr_volume);
} urr_volume_counters_map SEC(".maps");

/**
 * urr_config_map - Per-session URR configuration
 * Size: Runtime (MAX_PDU_SESSIONS)
 * Key:   SEID (__u64)
 * Value: struct urr_config
 *
 * Populated by control plane during PFCP Session Establishment
 * (TS 29.244 §7.2.2). Updated during Session Modification (§7.2.4).
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct urr_config);
} urr_config_map SEC(".maps");

/**
 * urr_report_ringbuf_map - Usage Report events → userspace
 * Size: 256 KB ring buffer
 *
 * Events are submitted when a Reporting Trigger fires (§8.2.53).
 * Userspace polls this ringbuf and constructs PFCP Session Report
 * Requests (§7.2.5) for each event.
 *
 * If the ringbuf is full, bpf_ringbuf_reserve() returns NULL and
 * the report is silently dropped. Userspace should size the ringbuf
 * appropriately for burst reporting rates.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} urr_report_ringbuf_map SEC(".maps");

/* ========================================================================== */
/*                      VOLUME MEASUREMENT (§8.2.45)                          */
/* ========================================================================== */

/**
 * @brief Update volume counters for this packet
 *
 * Atomically increments byte and packet counters for the current
 * direction (UL or DL) and totals. Uses __sync_fetch_and_add()
 * which compiles to BPF_ATOMIC_ADD (requires kernel >= 5.12).
 *
 * @param vol Pointer to volume counters in map
 * @param pkt_len Packet length in bytes (L2 frame)
 * @param is_uplink true for uplink, false for downlink
 */
static __always_inline void urr_update_volume(
    struct urr_volume* vol, __u32 pkt_len, bool is_uplink) {
  if (is_uplink) {
    __sync_fetch_and_add(&vol->ul_bytes, pkt_len);
    __sync_fetch_and_add(&vol->ul_packets, 1);
  } else {
    __sync_fetch_and_add(&vol->dl_bytes, pkt_len);
    __sync_fetch_and_add(&vol->dl_packets, 1);
  }

  __sync_fetch_and_add(&vol->total_bytes, pkt_len);
  __sync_fetch_and_add(&vol->total_packets, 1);
}

/* ========================================================================== */
/*                     USAGE REPORT SUBMISSION (§7.2.5)                       */
/* ========================================================================== */

/**
 * @brief Submit a Usage Report event to userspace via ringbuf
 *
 * Reserves space in the ringbuf, fills the event, and submits it.
 * If the ringbuf is full, the report is silently dropped.
 *
 * @param seid PFCP session ID
 * @param cfg URR configuration (for urr_id, monitoring_time)
 * @param vol Current volume counters (snapshot, not atomic read)
 * @param trigger Which reporting trigger fired (URR_TRIGGER_*)
 * @param now_ns Current timestamp from bpf_ktime_get_ns()
 */
static __always_inline void urr_submit_report(
    __u64 seid, struct urr_config* cfg, struct urr_volume* vol, __u8 trigger,
    __u64 now_ns) {
  struct urr_report_event* evt =
      bpf_ringbuf_reserve(&urr_report_ringbuf_map, sizeof(*evt), 0);

  if (!evt) {
    bpf_debug(
        "URR: Ringbuf full - Usage Report dropped "
        "SEID = %llu",
        seid);
    return;
  }

  evt->seid          = seid;
  evt->urr_id        = cfg->urr_id;
  evt->trigger       = trigger;
  evt->pad[0]        = 0;
  evt->pad[1]        = 0;
  evt->pad[2]        = 0;
  evt->timestamp_ns  = now_ns;
  evt->start_time_ns = cfg->monitoring_time_ns; Not an atomic read of the whole struct,
    * but individual fields are atomically updated — slight inconsistency
    * between fields is acceptable for reporting purposes.
    */
   /*
    * Snapshot current counters. Not an atomic read of the whole struct,
    * but individual fields are atomically updated — slight inconsistency
    * between fields is acceptable for reporting purposes.
    */
   evt->vol.ul_bytes          = vol->ul_bytes;
  evt->vol.dl_bytes           = vol->dl_bytes;
  evt->vol.ul_packets         = vol->ul_packets;
  evt->vol.dl_packets         = vol->dl_packets;
  evt->vol.total_bytes        = vol->total_bytes;
  evt->vol.total_packets      = vol->total_packets;
  evt->vol.dropped_dl_bytes   = vol->dropped_dl_bytes;   /* §8.2.49 */
  evt->vol.dropped_dl_packets = vol->dropped_dl_packets; /* §8.2.49 */

  bpf_ringbuf_submit(evt, 0);

  bpf_debug(
      "URR: Usage Report submitted - "
      "trigger = 0x%02x, URR-ID = %u, SEID = %llu",
      trigger, cfg->urr_id, seid);
}

/* ========================================================================== */
/*                   THRESHOLD / QUOTA CHECK (§8.2.46-48)                     */
/* ========================================================================== */

/**
 * @brief Check volume thresholds, quotas, and time conditions
 *
 * Evaluates all configured Reporting Triggers (§8.2.53) and submits
 * Usage Report events when conditions are met. Returns true if the
 * packet should be dropped due to quota exhaustion.
 *
 * @param seid PFCP session ID
 * @param cfg URR configuration (thresholds, quotas, triggers)
 * @param vol Current volume counters
 * @param is_uplink Traffic direction
 * @param now_ns Current timestamp
 * @return true if packet should be dropped (quota exhausted)
 */
static __always_inline bool urr_check_thresholds(
    __u64 seid, struct urr_config* cfg, struct urr_volume* vol, bool is_uplink,
    __u64 now_ns) {
  bool should_drop = false;

  /* -------------------------------------------------------------- */
  /*  Volume Threshold (§8.2.48) — informational report             */
  /* -------------------------------------------------------------- */
  if (cfg->reporting_triggers & URR_TRIGGER_VOLTH) {
    bool crossed = false;

    if (cfg->volume_threshold_total > 0 &&
        vol->total_bytes >= cfg->volume_threshold_total)
      crossed = true;

    if (is_uplink && cfg->volume_threshold_ul > 0 &&
        vol->ul_bytes >= cfg->volume_threshold_ul)
      crossed = true;

    if (!is_uplink && cfg->volume_threshold_dl > 0 &&
        vol->dl_bytes >= cfg->volume_threshold_dl)
      crossed = true;

    if (crossed) {
      bpf_debug(
          "URR: Volume Threshold crossed"
          "SEID = %llu, total = %llu bytes",
          seid, vol->total_bytes);
      urr_submit_report(seid, cfg, vol, URR_TRIGGER_VOLTH, now_ns);
    }
  }

  /* -------------------------------------------------------------- */
  /*  Volume Quota (§8.2.46) — enforcement, may DROP                */
  /* -------------------------------------------------------------- */
  if (cfg->reporting_triggers & URR_TRIGGER_VOLQU) {
    bool exhausted = false;

    if (cfg->volume_quota_total > 0 &&
        vol->total_bytes >= cfg->volume_quota_total)
      exhausted = true;

    if (is_uplink && cfg->volume_quota_ul > 0 &&
        vol->ul_bytes >= cfg->volume_quota_ul)
      exhausted = true;

    if (!is_uplink && cfg->volume_quota_dl > 0 &&
        vol->dl_bytes >= cfg->volume_quota_dl)
      exhausted = true;

    if (exhausted) {
      bpf_debug(
          "URR: Volume Quota exhausted "
          "SEID = %llu - enforcing DROP",
          seid);
      urr_submit_report(seid, cfg, vol, URR_TRIGGER_VOLQU, now_ns);
      should_drop = true;
    }
  }

  /* -------------------------------------------------------------- */
  /*  Time Threshold (§8.2.48) — informational report               */
  /* -------------------------------------------------------------- */
  if (cfg->reporting_triggers & URR_TRIGGER_TIMTH) {
    if (cfg->time_threshold_ns > 0 && cfg->monitoring_time_ns > 0) {
      __u64 elapsed = now_ns - cfg->monitoring_time_ns;

      if (elapsed >= cfg->time_threshold_ns) {
        bpf_debug(
            "URR: Time Threshold reached "
            "SEID = %llu, elapsed = %llu ns",
            seid, elapsed);
        urr_submit_report(seid, cfg, vol, URR_TRIGGER_TIMTH, now_ns);
      }
    }
  }

  /* -------------------------------------------------------------- */
  /*  Periodic Reporting (§8.2.72)                                  */
  /* -------------------------------------------------------------- */
  if (cfg->reporting_triggers & URR_TRIGGER_PERIO) {
    if (cfg->measurement_period_ns > 0) {
      __u64 since_last = now_ns - cfg->last_report_ns;

      if (since_last >= cfg->measurement_period_ns) {
        bpf_debug("URR: Periodic Report SEID = %llu", seid);
        urr_submit_report(seid, cfg, vol, URR_TRIGGER_PERIO, now_ns);

        /*
         * Update last_report_ns in-place. This is racy across CPUs
         * but acceptable — worst case we get a duplicate periodic
         * report, which userspace can deduplicate by timestamp.
         */
        cfg->last_report_ns = now_ns;
      }
    }
  }

  /* -------------------------------------------------------------- */
  /*  Time Quota (§8.2.47) — V17.10.0 addition: enforce DROP        */
  /* -------------------------------------------------------------- */
  if (cfg->reporting_triggers & URR_TRIGGER_TIMQU) {
    if (cfg->time_quota_ns > 0 && cfg->monitoring_time_ns > 0) {
      __u64 elapsed = now_ns - cfg->monitoring_time_ns;

      if (elapsed >= cfg->time_quota_ns) {
        bpf_debug(
            "URR: Time Quota exhausted (§8.2.47) "
            "SEID = %llu, elapsed = %llu ns — enforcing DROP",
            seid, elapsed);
        urr_submit_report(seid, cfg, vol, URR_TRIGGER_TIMQU, now_ns);
        should_drop = true;
      }
    }
  }

  /* -------------------------------------------------------------- */
  /*  Dropped DL Traffic Threshold (§8.2.49) — V17.10.0 addition   */
  /*                                                                */
  /*  The dropped_dl_bytes / dropped_dl_packets counters in         */
  /*  urr_volume are incremented by qer_apply.c (closed DL gate)   */
  /*  and bar_apply.c (buffer overflow drops).  We read them here   */
  /*  to evaluate the threshold and submit an informational report. */
  /* -------------------------------------------------------------- */
  if (cfg->reporting_triggers & URR_TRIGGER_DROTH) {
    bool droth_crossed = false;

    if (cfg->dropped_dl_threshold_bytes > 0 &&
        vol->dropped_dl_bytes >= cfg->dropped_dl_threshold_bytes)
      droth_crossed = true;

    if (cfg->dropped_dl_threshold_pkts > 0 &&
        vol->dropped_dl_packets >= cfg->dropped_dl_threshold_pkts)
      droth_crossed = true;

    if (droth_crossed) {
      bpf_debug(
          "URR: Dropped DL Threshold crossed (§8.2.49) "
          "SEID = %llu, dropped_dl_bytes = %llu, dropped_dl_pkts = %llu",
          seid, vol->dropped_dl_bytes, vol->dropped_dl_packets);
      urr_submit_report(seid, cfg, vol, URR_TRIGGER_DROTH, now_ns);
      /* Informational only — no DROP enforced for DROTH */
    }
  }

  return should_drop;
}

/* ========================================================================== */
/*                         URR APPLICATION                                    */
/* ========================================================================== */

SEC("xdp")
int urr_apply(struct xdp_md* ctx) {
  bpf_debug("=== URR Apply ===");

  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("Error: Failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  u64 seid    = pctx->seid;
  __u32 flags = pctx->rules_enabled;

  /* ---------------------------------------------------------------- */
  /*  Step 1: Lookup volume counters for this session (§8.2.45)      */
  /* ---------------------------------------------------------------- */
  struct urr_volume* vol = bpf_map_lookup_elem(&urr_volume_counters_map, &seid);

  if (!vol) {
    /*
     * No volume counter entry means control plane didn't create one
     * for this session. Skip measurement, continue forwarding.
     */
    bpf_debug(
        "URR: No volume counters for SEID = %llu - "
        "skipping measurement",
        seid);
    goto dispatch_next;
  }

  /* ---------------------------------------------------------------- */
  /*  Step 2: Volume Measurement — update counters (§8.2.45)         */
  /* ---------------------------------------------------------------- */
  __u32 pkt_len  = (__u32) (ctx->data_end - ctx->data);
  bool is_uplink = IS_UPLINK(pctx->session_type);

  urr_update_volume(vol, pkt_len, is_uplink);

  bpf_debug(
      "URR: Volume updated SEID = %llu %s +%u bytes "
      "(total = %llu bytes, total = %llu pkts)",
      seid, is_uplink ? "UL" : "DL", pkt_len, vol->total_bytes,
      vol->total_packets);

  /* ---------------------------------------------------------------- */
  /*  Step 3: Lookup URR configuration (thresholds, quotas)          */
  /* ---------------------------------------------------------------- */
  struct urr_config* cfg = bpf_map_lookup_elem(&urr_config_map, &seid);

  if (!cfg) {
    /*
     * Volume counters exist but no config means measure-only mode —
     * no thresholds or quotas to enforce. Userspace can poll the
     * counters map directly.
     */
    bpf_debug(
        "URR: No config for SEID = %llu - "
        "measurement only, no thresholds ",
        seid);
    goto dispatch_next;
  }

  bpf_debug(
      "URR: Config found - URR-ID = %u, triggers = 0x%02x", cfg->urr_id,
      cfg->reporting_triggers);

  /* ---------------------------------------------------------------- */
  /*  Step 4: Check thresholds and enforce quotas (§8.2.46-48)       */
  /* ---------------------------------------------------------------- */
  __u64 now_ns = bpf_ktime_get_ns();

  bool should_drop = urr_check_thresholds(seid, cfg, vol, is_uplink, now_ns);

  if (should_drop) {
    bpf_debug(
        "URR: Quota exhausted - overriding to "
        "FINAL_ACTION_DROP");
    pctx->final_action = FINAL_ACTION_DROP;
  }

dispatch_next:
  /* Dispatch to next enabled program: [MAR] → execute */
  dispatch_after_urr(ctx, flags);

  /* MAR disabled or tail call failed — execute final action now */
  bpf_debug("URR: No downstream rules - executing final action");
  EXECUTE_FINAL_ACTION(ctx, pctx);
}

char _license[] SEC("license") = "GPL";
