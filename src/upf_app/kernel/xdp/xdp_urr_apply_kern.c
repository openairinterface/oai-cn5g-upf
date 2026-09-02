/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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

#include "custom_types.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"
#include "utils/types.h"

#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_pdr.h"

#include "pipeline_maps.h"
#include "interfaces_types.h"
#include "interfaces_maps.h" /* redirect_interfaces_map (via EXECUTE_FINAL_ACTION) */
#include "tail_call_dispatcher.h"
#include "stats_maps.h"
#include "stats_types.h"
#include "urr_maps.h"

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
  evt->start_time_ns = cfg->monitoring_time_ns;
  /*  Not an atomic read of the whole struct,
   * but individual fields are atomically updated — slight inconsistency
   * between fields is acceptable for reporting purposes.
   */
  /*
   * Snapshot current counters. Not an atomic read of the whole struct,
   * but individual fields are atomically updated — slight inconsistency
   * between fields is acceptable for reporting purposes.
   */
  evt->vol.ul_bytes           = vol->ul_bytes;
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

  bpf_debug("URR: Vol SEID=%llu +%u bytes", seid, pkt_len);
  bpf_debug(
      "URR: total=%llu bytes %llu pkts", vol->total_bytes, vol->total_packets);

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
