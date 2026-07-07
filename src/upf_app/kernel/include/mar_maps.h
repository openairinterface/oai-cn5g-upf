/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __MAR_MAPS_H__
#define __MAR_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "mar_types.h"
#include "upf_map_limits.h"

/* ==========================================================================
 * mar_config_map
 * ========================================================================== */

/**
 * @brief Per-session MAR steering configuration.
 *
 * Key:   __u64              SEID
 * Value: struct mar_config  {mar_id, steer_mode, access paths, weights}
 * Size:  MAX_PDU_SESSIONS
 *
 * Written by SessionProgramManager when Create MAR (§7.5.2.8) or
 * Update MAR (§7.5.4.13) IEs are present in a PFCP message.
 * Only sessions with ATSSS capability have entries in this map.
 *
 * Read by xdp_mar_apply_kern.c on every packet to determine which
 * access path to use for forwarding.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct mar_config);
} mar_config_map SEC(".maps");

/* ==========================================================================
 * mar_access_state_map
 * ========================================================================== */

/**
 * @brief Per-session access-path RTT and liveness state.
 *
 * Key:   __u64                    SEID
 * Value: struct mar_access_state  {rtt_3gpp_ns, rtt_non3gpp_ns,
 *                                  rtt_updated_ns, status_3gpp,
 *                                  status_non3gpp}
 * Size:  MAX_PDU_SESSIONS
 *
 * Updated by the userspace probe daemon (ICMP / GTP-U echo measurements).
 * Read by xdp_mar_apply_kern.c for:
 *   - STEER_SMALLEST_DELAY:  compare rtt_3gpp_ns vs rtt_non3gpp_ns
 *   - STEER_ACTIVE_STANDBY:  check status_* for failover detection
 *   - STEER_PRIORITY_BASED:  check preferred-path availability
 *
 * The probe daemon is the sole writer; the XDP program is read-only.
 * No atomic operations are required on this map.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct mar_access_state);
} mar_access_state_map SEC(".maps");

#endif /* __MAR_MAPS_H__ */
