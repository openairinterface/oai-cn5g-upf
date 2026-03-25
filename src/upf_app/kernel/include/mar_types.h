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

/**
 * @file  mar_types.h
 * @brief Multi-Access Rule (MAR) data structures for ATSSS.
 *
 * Defines all types shared between xdp_mar_apply_kern.c and the
 * userspace path probe daemon:
 *
 *   - enum mar_access_type   3GPP vs non-3GPP access path identifier
 *   - enum mar_steer_mode    ATSSS steering algorithm selection
 *   - enum mar_path_status   per-access-path liveness state
 *   - struct mar_config      CP-configured MAR rule
 *   - struct mar_access_state runtime RTT / liveness state
 *   - REDIRECT_N3 / REDIRECT_N9 interface slot constants
 *
 * Contains only plain-C types — no BPF map definitions.
 *
 * 3GPP Ref: 3GPP TS 29.244 V17.10.0
 *   §8.2.123  MAR ID
 *   §8.2.124  Steering Functionality
 *   §8.2.125  Steering Mode
 *   §8.2.126  Weight
 *   §8.2.127  Priority
 *   TS 23.501 §5.32  — ATSSS (Access Traffic Steering, Switching, Splitting)
 */

/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Refactoring — split into *_types.h / *_maps.h pairs,
 *              corrected 3GPP TS 29.244 V17.10.0 section references,
 *              removed Unicode symbols, applied Boy Scout cleanup.
 */

#ifndef __MAR_TYPES_H__
#define __MAR_TYPES_H__

#include <linux/types.h>

/* ==========================================================================
 * Access type enumeration
 * ========================================================================== */

/**
 * @brief UE access path type for ATSSS multi-access sessions.
 *
 * A UE with ATSSS capability can register simultaneously over both
 * access paths. The MAR steers downlink traffic via one or both paths
 * depending on the configured Steering Mode.
 */
enum mar_access_type {
  ACCESS_3GPP     = 0, /**< 3GPP access: RAN / gNB -> N3 interface   */
  ACCESS_NON_3GPP = 1, /**< Non-3GPP: WLAN / N3IWF -> N9 interface   */
};

/* ==========================================================================
 * Steering mode enumeration  (§8.2.125)
 * ========================================================================== */

/**
 * @brief ATSSS traffic steering algorithm.
 *
 * Carried in the Steering Mode IE (§8.2.125) from SMF to UPF during
 * PFCP Session Establishment / Modification.
 */
enum mar_steer_mode {
  STEER_ACTIVE_STANDBY = 0, /**< Primary path + failover on loss       */
  STEER_SMALLEST_DELAY = 1, /**< Dynamic RTT-based path selection      */
  STEER_LOAD_BALANCE   = 2, /**< Per-flow hash weight distribution     */
  STEER_PRIORITY_BASED = 3, /**< Ordered priority with fallback        */
};

/* ==========================================================================
 * Access path status
 * ========================================================================== */

/**
 * @brief Per-access-path liveness status.
 *
 * Maintained by the userspace probe daemon.
 * Written into mar_access_state_map so the XDP program can detect
 * path failures for STEER_ACTIVE_STANDBY failover.
 */
enum mar_path_status {
  PATH_STATUS_UP   = 0, /**< Path is operational (heartbeat alive)  */
  PATH_STATUS_DOWN = 1, /**< Path has failed (heartbeat lost)       */
};

/* ==========================================================================
 * redirect_interfaces_map slot constants for MAR
 * ========================================================================== */

/**
 * Slot indices into redirect_interfaces_map (BPF_MAP_TYPE_DEVMAP).
 * Slots 0 and 1 are already used by the FAR for UL/DL redirect.
 * MAR adds slot 2 for the non-3GPP N9 interface.
 *
 * Userspace must populate redirect_interfaces_map[REDIRECT_N9] with
 * the ifindex of the N9 / N3IWF interface when ATSSS is enabled.
 */
#define REDIRECT_N3 1 /**< Downlink via 3GPP N3 — same as FAR DL redirect */
#define REDIRECT_N9 2 /**< Downlink via non-3GPP N9 / N3IWF               */

/* ==========================================================================
 * MAR rule configuration  (CP -> data plane)
 * ========================================================================== */

/**
 * @brief MAR steering configuration pushed by the control plane.
 *
 * Stored in mar_config_map (keyed by SEID).
 * Populated during PFCP Session Establishment (§7.5.2) or Modification
 * (§7.5.4) when Create MAR / Update MAR IEs are present.
 * Only sessions with ATSSS capability have entries in this map.
 */
struct mar_config {
  __u16 mar_id;         /**< MAR ID (§8.2.123)                       */
  __u8 steer_mode;      /**< enum mar_steer_mode (§8.2.125)          */
  __u8 active_access;   /**< enum mar_access_type — primary path      */
  __u8 standby_access;  /**< enum mar_access_type — backup path       */
  __u8 priority_access; /**< enum mar_access_type — preferred path
                         *   (for STEER_PRIORITY_BASED mode)         */

  /* Load balancing weights (sum should equal 100) */
  __u8 weight_3gpp;    /**< Traffic weight for 3GPP (0-100)          */
  __u8 weight_non3gpp; /**< Traffic weight for non-3GPP (0-100)      */
};

/* ==========================================================================
 * MAR access-path state  (data plane, updated by userspace probe daemon)
 * ========================================================================== */

/**
 * @brief Per-session access-path RTT measurements and liveness state.
 *
 * Maintained by the userspace probe daemon via ICMP / GTP-U echo.
 * Stored in mar_access_state_map (keyed by SEID).
 * Read by xdp_mar_apply_kern.c to make per-packet steering decisions.
 *
 * Probe mechanism:
 *   - ICMP echo to gNB (3GPP path) and N3IWF (non-3GPP path)
 *   - RTT measured from request send to reply receive
 *   - status set to PATH_STATUS_DOWN when N consecutive probes are lost
 *   - Probe interval is deployment-specific (typically 100 ms - 1 s)
 */
struct mar_access_state {
  __u64 rtt_3gpp_ns;    /**< Last measured RTT on 3GPP path (ns)     */
  __u64 rtt_non3gpp_ns; /**< Last measured RTT on non-3GPP path (ns) */
  __u64 rtt_updated_ns; /**< bpf_ktime_get_ns() of last RTT update   */
  __u8 status_3gpp;     /**< enum mar_path_status — 3GPP path        */
  __u8 status_non3gpp;  /**< enum mar_path_status — non-3GPP path    */
  __u8 pad[6];
};

#endif /* __MAR_TYPES_H__ */
