/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __URR_TYPES_H__
#define __URR_TYPES_H__

#include <linux/types.h>

/* ==========================================================================
 * Reporting trigger flags  (§8.2.19)
 * ========================================================================== */

#define URR_TRIGGER_VOLTH (1U << 0) /**< Volume Threshold reached (§8.2.13) */
#define URR_TRIGGER_VOLQU (1U << 1) /**< Volume Quota exhausted  (§8.2.50)  */
#define URR_TRIGGER_TIMTH (1U << 2) /**< Time Threshold reached  (§8.2.14)  */
#define URR_TRIGGER_TIMQU (1U << 3) /**< Time Quota exhausted    (§8.2.51)  */
#define URR_TRIGGER_PERIO (1U << 4) /**< Periodic measurement    (§8.2.42)  */
#define URR_TRIGGER_START (1U << 5) /**< Start of traffic        (§8.2.19)  */
#define URR_TRIGGER_STOPT (1U << 6) /**< Stop of traffic         (§8.2.19)  */
#define URR_TRIGGER_DROTH (1U << 7) /**< Dropped DL threshold    (§8.2.49)  */

/* ==========================================================================
 * Volume counters  (§8.2.44)
 * ========================================================================== */

/**
 * @brief Per-session URR volume counters.
 *
 * Stored in urr_volume_counters_map (keyed by SEID).
 * Updated atomically by the XDP program via __sync_fetch_and_add()
 * (compiles to BPF_ATOMIC_ADD, requires kernel ≥ 5.12).
 *
 * Zeroed by the control plane on session establishment.
 * Userspace may read at any time without resetting.
 *
 * The dropped_dl_* fields are written by xdp_qer_apply_kern.c and
 * xdp_bar_apply_kern.c when a DL packet is dropped, then read here
 * to evaluate the Dropped DL Traffic Threshold trigger (§8.2.49).
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

/* ==========================================================================
 * URR configuration  (CP → data plane)
 * ========================================================================== */

/**
 * @brief URR thresholds, quotas, and measurement parameters.
 *
 * Populated by control plane during PFCP Session Establishment
 * (TS 29.244 §7.2.2) or Modification (TS 29.244 §7.2.4).
 *
 * A value of 0 means the corresponding threshold/quota is not active.
 */
struct urr_config {
  __u32 urr_id;            /**< URR ID (§8.2.54)                         */
  __u8 reporting_triggers; /**< Reporting Triggers bitmask (§8.2.19)    */
  __u8 pad[3];

  /* Volume Threshold (§8.2.13) — generate report when crossed           */
  __u64 volume_threshold_total; /**< Total volume threshold (bytes)      */
  __u64 volume_threshold_ul;    /**< Uplink volume threshold (bytes)     */
  __u64 volume_threshold_dl;    /**< Downlink volume threshold (bytes)   */

  /* Volume Quota (§8.2.50) — DROP packets when exhausted                */
  __u64 volume_quota_total; /**< Total volume quota (bytes)              */
  __u64 volume_quota_ul;    /**< Uplink volume quota (bytes)             */
  __u64 volume_quota_dl;    /**< Downlink volume quota (bytes)           */

  /* Time Threshold (§8.2.14) — generate report after duration           */
  __u64 time_threshold_ns; /**< Time threshold (nanoseconds)             */

  /* Time Quota (§8.2.51) — V17.10.0 addition: DROP when exceeded       */
  __u64 time_quota_ns; /**< Max allowed session duration (ns); 0=off */

  /* Dropped DL Traffic Threshold (§8.2.49) — V17.10.0 addition         */
  __u64 dropped_dl_threshold_bytes; /**< Dropped DL byte threshold; 0=off */
  __u32 dropped_dl_threshold_pkts;  /**< Dropped DL pkt threshold; 0=off  */
  __u32 pad2;

  /* Monitoring Time (§8.2.15) — measurement start timestamp             */
  __u64 monitoring_time_ns; /**< Set to bpf_ktime_get_ns() at start      */

  /* Measurement Period (§8.2.42) — periodic reporting interval          */
  __u64 measurement_period_ns; /**< Periodic report interval (ns)        */
  __u64 last_report_ns;        /**< Timestamp of last periodic report    */
};

/* ==========================================================================
 * Usage Report event  (data plane → userspace)
 * ========================================================================== */

/**
 * @brief Usage Report event sent to userspace via ringbuf.
 *
 * Produced by the XDP program, consumed by xdp_urr_apply_user.cpp.
 * Userspace reads this event and constructs a PFCP Session Report
 * Request (TS 29.244 §7.2.5) with a Usage Report IE
 * (Table 7.5.8.3-1) and sends it to the SMF.
 */
struct urr_report_event {
  __u64 seid;   /**< PFCP Session Endpoint Identifier    */
  __u32 urr_id; /**< URR ID that triggered the report    */
  __u8 trigger; /**< Which trigger fired (URR_TRIGGER_*) */
  __u8 pad[3];
  struct urr_volume vol; /**< Snapshot of volume counters         */
  __u64 timestamp_ns;    /**< bpf_ktime_get_ns() at report time   */
  __u64 start_time_ns;   /**< Measurement start time (§8.2.15)   */
};

#endif /* __URR_TYPES_H__ */
