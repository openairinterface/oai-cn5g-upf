/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_URR_H
#define _PFCP_URR_H

#include "ie/reporting_triggers.h"
#include "ie/measurement_method.h"
#include "ie/measurement_period.h"
#include "ie/time_threshold.h"
#include "ie/time_quota.h" /* §8.2.47 — V17.10.0 addition */
#include "ie/monitoring_time.h"
/* Control-plane only — not used by urr_apply XDP program:
 * #include "ie/quota_holding_time.h"    post-depletion timer managed by
 * user-space
 */
#include "ie/dropped_dl_traffic_threshold.h" /* §8.2.49 — V17.10.0 addition */
#include "ie/group_ie/volume_threshold.h"
#include "ie/group_ie/volume_quota.h"
/* Control-plane / application-level only — not used by urr_apply XDP program:
 * #include "ie/quota_holding_time.h"    §-ref unconfirmed; post-depletion CP
 * timer #include "ie/event_quota.h"           §8.2.82; application-event
 * signals, not XDP-visible #include "ie/event_threshold.h"       §8.2.83; same
 * reason
 */

/**
 * @struct pfcp_urr
 * @brief Usage Reporting Rule — BPF map value  (§7.5.2.6)
 *
 * Written by URRProgram::Setup(); read by the urr_apply BPF program
 * for per-session volume and time accounting.
 * Volume counters are stored separately in urr_volume_counters_map and updated
 * atomically by the data plane; this struct carries thresholds/triggers.
 *
 * V17.10.0 additions (active data-plane fields):
 *   time_quota, dropped_dl_traffic_threshold — require ConvertUrr() update.
 *
 * Control-plane / application-level IEs (not used by urr_apply XDP program):
 *   quota_holding_time  — post-depletion countdown timer; user-space state
 * machine only. event_quota         — application-detection event signals; XDP
 * has no visibility into application-level events (§8.2.82). event_threshold —
 * same reason (§8.2.83).
 */
struct pfcp_urr {
  __u32 urr_id;  ///< URR identifier (§8.2.54)
  struct reporting_triggers
      reporting_triggers;  ///< Volume/time/periodic trigger flags (§8.2.53)
  struct measurement_method
      measurement_method;  ///< Volume / Duration / Event (§8.2.62)
  struct measurement_period
      measurement_period;  ///< Periodic reporting interval (§8.2.72)
  struct time_threshold
      time_threshold;  ///< Time-based reporting threshold (§-ref unconfirmed —
                       ///< verify against V17.10.0)
  struct monitoring_time
      monitoring_time;  ///< Measurement start/reset timestamp (§8.2.15)
  struct volume_threshold
      volume_threshold;  ///< Volume reporting thresholds UL/DL/total (§8.2.48)
  struct volume_quota
      volume_quota;              ///< Volume usage quotas UL/DL/total (§8.2.46)
  struct time_quota time_quota;  ///< Maximum allowed usage duration (§8.2.47)
  struct dropped_dl_traffic_threshold
      dropped_dl_traffic_threshold;  ///< Dropped DL packet reporting threshold
                                     ///< (§8.2.49)
  /* Control-plane / application-level only — not read by urr_apply XDP program:
   * struct quota_holding_time quota_holding_time;  post-depletion CP timer
   * (§-ref unconfirmed) struct event_quota event_quota; application-event quota
   * ceiling (§8.2.82) struct event_threshold event_threshold; application-event
   * reporting trigger (§8.2.83)
   */
} __attribute__((packed));

#endif /* _PFCP_URR_H */
