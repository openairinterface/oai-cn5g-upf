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
 * Changes:     V17.10.0 §-ref corrections throughout:
 *                - MAR ID:               §8.2.74 → §8.2.123
 *                - Steering Functionality: §8.2.76 → §8.2.124 (was labelled
 *                  "Steer Functioning" in pre-R17 numbering).
 *                - Steering Mode:        §8.2.76 → §8.2.125
 *                - Access Forwarding Action Information: §8.2.75 → §8.2.126/127
 *                  (AFAI Weight / Priority respectively in V17.10.0).
 *              V17.10.0 integration — use pctx->pdr_mar_id for MAR lookup:
 *                - pdr_match.c now propagates pdr->mar_id (§8.2.123) to
 *                  pctx->pdr_mar_id.  For sessions where the matched PDR
 *                  has no associated MAR (pdr_mar_id == 0) we short-circuit
 *                  before the map lookup, saving one bpf_map_lookup_elem()
 *                  on the hot path for all non-ATSSS sessions.
 *              mar_config struct — mar_id type corrected __u32 → __u16
 *                to match pfcp_mar.h (§8.2.123 specifies a 16-bit value).
 *              Boy Scout cleanup:
 *                - Updated all §-refs in @file, inline comments, and
 *                  enum/struct field comments.
 *                - Replaced bare @file block with changelog + guards.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §8.2.123  MAR ID
 *              §8.2.124  Steering Functionality
 *              §8.2.125  Steering Mode
 *              §8.2.126  AFAI (Weight)     §8.2.127  AFAI (Priority)
 *              TS 23.501 §5.32   ATSSS
 *              TS 23.501 §5.32.4 Steering Modes
 */
// clang-format on

/**
 * @file mar_apply.c
 * @brief MAR (Multi-Access Rule) — ATSSS access steering, switching, splitting
 *
 * Only reached when RULE_MAR_ENABLED is set in pctx->rules_enabled.
 * Last program in the normal forwarding chain — executes final_action.
 *
 * Per 3GPP TS 29.244 §8.2.123-127 and TS 23.501 §5.32 (ATSSS), MAR
 * controls multi-access traffic handling for UEs with simultaneous
 * connectivity over two access paths:
 *
 *   Access types (TS 23.501 §5.32.1):
 *     - 3GPP access:     RAN via gNB → N3 interface
 *     - Non-3GPP access: WLAN/fixed broadband → N9/N3IWF interface
 *
 *   Steering Modes (TS 23.501 §5.32.4, §8.2.125):
 *     - Active-Standby:   Primary/backup access, failover on path loss
 *     - Smallest Delay:   Route via lowest-RTT path (dynamic)
 *     - Load Balancing:   Distribute flows across both paths
 *     - Priority-Based:   Prefer high-priority access, fallback on failure
 *
 *   Operations (TS 23.501 5.32):
 *     - Steering:   Initial access selection for new flows
 *     - Switching:  Move existing flow between accesses mid-session
 *     - Splitting:  Distribute a single flow across both accesses
 *                   (MPTCP at transport layer, ATSSS-LL at lower layer)
 *
 * Architecture note:
 *   In the current chain (FAR -> QER -> URR -> MAR), FAR applies Outer Header
 *   Creation before MAR evaluates. MAR can override the redirect target
 *   (N3 vs N9 interface) for downlink. For uplink, the access path is
 *   already determined by the incoming interface -- MAR is a no-op.
 *
 *   For scenarios requiring different encapsulation per access (e.g.,
 *   different F-TEIDs for N3 vs N9), a future enhancement would have
 *   MAR evaluate before FAR, or use per-access FAR IDs. The current
 *   implementation handles the common case where both paths share the
 *   same tunnel parameters and only the egress interface differs.
 *
 * Chain: ... -> [URR] -> [MAR_APPLY] -> execute final XDP action
 *        (MAR is the terminal node in the normal forwarding chain)
 *
 * @see 3GPP TS 29.244 §8.2.123 - MAR ID
 * @see 3GPP TS 29.244 §8.2.124 - Steering Functionality
 * @see 3GPP TS 29.244 §8.2.125 - Steering Mode
 * @see 3GPP TS 29.244 §8.2.126 - Access Forwarding Action Information (Weight)
 * @see 3GPP TS 29.244 §8.2.127 - Access Forwarding Action Information
 * (Priority)
 * @see 3GPP TS 23.501 §5.32   - ATSSS
 * @see 3GPP TS 23.501 §5.32.4 - Steering Modes
 */

#define KBUILD_MODNAME mar_apply

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
/*                      MAR DATA STRUCTURES                                   */
/* ========================================================================== */

/**
 * @brief Access type for multi-access sessions (TS 23.501 5.32.1)
 *
 * A UE with ATSSS capability registers over both access types
 * simultaneously. The UPF routes downlink traffic via one or both
 * based on the MAR steer mode.
 */
enum mar_access_type {
  ACCESS_3GPP     = 0, /**< 3GPP access via RAN/gNB -> N3 interface    */
  ACCESS_NON_3GPP = 1, /**< Non-3GPP access via WLAN/N3IWF -> N9       */
};

/**
 * @brief ATSSS steer mode (TS 23.501 §5.32.4, TS 29.244 §8.2.125)
 *
 * Determines how traffic is distributed across the two access paths.
 * The Steering Mode IE (§8.2.125) carries the steer mode from
 * SMF to UPF in PFCP Session Establishment/Modification.
 */
enum mar_steer_mode {
  STEER_ACTIVE_STANDBY = 0, /**< Primary/backup, failover on loss     */
  STEER_SMALLEST_DELAY = 1, /**< Dynamic RTT-based path selection     */
  STEER_LOAD_BALANCE   = 2, /**< Per-flow hash distribution           */
  STEER_PRIORITY_BASED = 3, /**< Priority ordering with fallback      */
};

/**
 * @brief Access path status for failover detection
 */
enum mar_path_status {
  PATH_STATUS_UP   = 0, /**< Access path is operational               */
  PATH_STATUS_DOWN = 1, /**< Access path has failed (heartbeat lost)  */
};

/**
 * @brief MAR rule configuration (TS 29.244 §8.2.123-127)
 *
 * Populated by control plane during PFCP Session Establishment (§7.2.2)
 * or Modification (§7.2.4). Contains the Steering Functionality IE (§8.2.124),
 * Steering Mode IE (§8.2.125) and Access Forwarding Action Information IEs
 * (§8.2.126 / §8.2.127).
 *
 * The weight fields are used by STEER_LOAD_BALANCE mode to control
 * the traffic distribution ratio (e.g., 70/30 split).
 */
struct mar_config {
  __u16 mar_id;         /**< MAR ID (§8.2.123)                      */
  __u8 steer_mode;      /**< enum mar_steer_mode (§8.2.125)         */
  __u8 active_access;   /**< enum mar_access_type — primary path     */
  __u8 standby_access;  /**< enum mar_access_type — backup path      */
  __u8 priority_access; /**< enum mar_access_type — preferred path
                         *   (for STEER_PRIORITY_BASED mode)         */

  /* Load balancing weights (sum should equal 100) */
  __u8 weight_3gpp;    /**< Traffic weight for 3GPP (0-100)         */
  __u8 weight_non3gpp; /**< Traffic weight for non-3GPP (0-100)     */
};

/**
 * @brief Per-session access path state (heartbeat, RTT, status)
 *
 * Maintained by userspace through periodic probes:
 *   - Heartbeat probes detect path failure for Active-Standby failover
 *   - RTT measurements drive Smallest-Delay path selection
 *   - Path status is set to DOWN when probe response is lost
 *
 * Userspace probe mechanism:
 *   - ICMP/GTP-U echo to gNB (3GPP path) and N3IWF (non-3GPP path)
 *   - Updates map entries with measured RTT and liveness status
 *   - Probe interval is deployment-specific (typically 100ms-1s)
 */
struct mar_access_state {
  /* RTT measurements (nanoseconds) -- for STEER_SMALLEST_DELAY */
  __u64 rtt_3gpp_ns;    /**< Last measured RTT on 3GPP path (ns)    */
  __u64 rtt_non3gpp_ns; /**< Last measured RTT on non-3GPP path     */
  __u64 rtt_updated_ns; /**< Timestamp of last RTT update           */

  /* Path status -- for STEER_ACTIVE_STANDBY failover */
  __u8 status_3gpp;    /**< enum mar_path_status -- 3GPP path     */
  __u8 status_non3gpp; /**< enum mar_path_status -- non-3GPP path */
  __u8 pad[6];
};

/**
 * @brief Redirect interface indices for access paths
 *
 * Keys into redirect_interfaces_map (BPF_MAP_TYPE_DEVMAP).
 * Indices 0 (UPLINK -> N6) and 1 (DOWNLINK -> N3) are used by the
 * existing FAR. MAR adds index 2 for the non-3GPP N9 interface.
 *
 * Userspace must populate redirect_interfaces_map[REDIRECT_N9]
 * with the ifindex of the N9/N3IWF interface when ATSSS is enabled.
 */
#define REDIRECT_N3 1 /**< Same as DOWNLINK -- 3GPP DL via N3     */
#define REDIRECT_N9 2 /**< Non-3GPP DL via N9/N3IWF               */

/* ========================================================================== */
/*                            MAR BPF MAPS                                    */
/* ========================================================================== */

/**
 * mar_config_map - Per-session MAR configuration
 * Size: Runtime (MAX_PDU_SESSIONS)
 * Key:   SEID (__u64)
 * Value: struct mar_config
 *
 * Populated by control plane when Create MAR or Update MAR IEs
 * are present in PFCP Session Establishment/Modification.
 * Only sessions with ATSSS have entries in this map.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct mar_config);
} mar_config_map SEC(".maps");

/**
 * mar_access_state_map - Per-session access path state (RTT, status)
 * Size: Runtime (MAX_PDU_SESSIONS)
 * Key:   SEID (__u64)
 * Value: struct mar_access_state
 *
 * Updated by userspace probe daemon. Read by BPF for:
 *   - STEER_SMALLEST_DELAY: compare rtt_3gpp_ns vs rtt_non3gpp_ns
 *   - STEER_ACTIVE_STANDBY: check path status for failover
 *   - STEER_PRIORITY_BASED: check preferred path availability
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u64);
  __type(value, struct mar_access_state);
} mar_access_state_map SEC(".maps");

/* ========================================================================== */
/*                     ACCESS SELECTION -- STEER MODES                        */
/* ========================================================================== */

/**
 * @brief Active-Standby steering (TS 23.501 5.32.4)
 *
 * Uses the configured active access. Fails over to standby if the
 * active path is down (detected by userspace heartbeat probes).
 *
 * @param cfg MAR configuration
 * @param state Access path state (liveness from probes)
 * @return Selected access type
 */
static __always_inline __u8 mar_steer_active_standby(
    struct mar_config* cfg, struct mar_access_state* state) {
  __u8 active  = cfg->active_access;
  __u8 standby = cfg->standby_access;

  if (active == ACCESS_3GPP && state->status_3gpp == PATH_STATUS_DOWN) {
    bpf_debug(
        "MAR: Active-Standby failover -- 3GPP DOWN, "
        "switching to non-3GPP");
    return standby;
  }

  if (active == ACCESS_NON_3GPP && state->status_non3gpp == PATH_STATUS_DOWN) {
    bpf_debug(
        "MAR: Active-Standby failover -- non-3GPP DOWN, "
        "switching to 3GPP");
    return standby;
  }

  return active;
}

/**
 * @brief Smallest-Delay steering (TS 23.501 5.32.4)
 *
 * Selects the access path with the lowest measured RTT.
 * Falls back to 3GPP if RTT data is unavailable or stale.
 *
 * RTT measurements are populated by userspace probe daemon.
 * Staleness threshold: RTT data older than 10 seconds is considered
 * unreliable (configurable in practice).
 *
 * @param state Access path state (RTT from probes)
 * @param now_ns Current timestamp
 * @return Selected access type
 */
#define RTT_STALENESS_NS (10ULL * 1000000000ULL) /* 10 seconds */

static __always_inline __u8
mar_steer_smallest_delay(struct mar_access_state* state, __u64 now_ns) {
  /* Check RTT data freshness */
  if (state->rtt_updated_ns == 0 ||
      (now_ns - state->rtt_updated_ns) > RTT_STALENESS_NS) {
    bpf_debug(
        "MAR: Smallest-Delay -- RTT stale, "
        "defaulting to 3GPP");
    return ACCESS_3GPP;
  }

  /* Both paths must have valid RTT measurements */
  if (state->rtt_3gpp_ns == 0 || state->rtt_non3gpp_ns == 0) {
    bpf_debug(
        "MAR: Smallest-Delay -- incomplete RTT, "
        "defaulting to 3GPP");
    return ACCESS_3GPP;
  }

  if (state->rtt_non3gpp_ns < state->rtt_3gpp_ns) {
    bpf_debug(
        "MAR: Smallest-Delay -- non-3GPP wins "
        "(RTT %llu < %llu ns)",
        state->rtt_non3gpp_ns, state->rtt_3gpp_ns);
    return ACCESS_NON_3GPP;
  }

  bpf_debug(
      "MAR: Smallest-Delay -- 3GPP wins "
      "(RTT %llu <= %llu ns)",
      state->rtt_3gpp_ns, state->rtt_non3gpp_ns);
  return ACCESS_3GPP;
}

/**
 * @brief Load-Balancing steering (TS 23.501 5.32.4)
 *
 * Distributes flows across both access paths based on a hash of the
 * 5-tuple from the packet context. The weight_3gpp field determines
 * the percentage of flows sent over 3GPP (0-100); the remainder
 * goes over non-3GPP.
 *
 * This is per-flow (not per-packet) -- the same 5-tuple always maps
 * to the same access, ensuring in-order delivery.
 *
 * Hash: Knuth multiplicative hash of XOR-folded 5-tuple, then
 * modulo 100 to compare against the weight threshold.
 *
 * @param cfg MAR configuration (weight_3gpp, weight_non3gpp)
 * @param pctx Packet context (5-tuple for flow hash)
 * @return Selected access type
 */
static __always_inline __u8
mar_steer_load_balance(struct mar_config* cfg, struct packet_context* pctx) {
  /*
   * Compute a deterministic flow hash from the 5-tuple.
   * XOR-fold all fields, then Knuth multiplicative mix.
   */
  __u32 hash =
      pctx->pkt_filter_src_ip ^ pctx->pkt_filter_dst_ip ^
      ((__u32) pctx->pkt_filter_src_port << 16 | pctx->pkt_filter_dst_port) ^
      (__u32) pctx->pkt_filter_protocol;

  hash = hash * 2654435761U;
  hash = hash >> 16;

  __u32 bucket = hash % 100;

  if (bucket < cfg->weight_3gpp) {
    bpf_debug(
        "MAR: Load-Balance -- hash = %u bucket = %u < weight = %u "
        "-> 3GPP",
        hash, bucket, cfg->weight_3gpp);
    return ACCESS_3GPP;
  }

  bpf_debug(
      "MAR: Load-Balance -- hash = %u bucket = %u >= weight = %u "
      "-> non-3GPP",
      hash, bucket, cfg->weight_3gpp);
  return ACCESS_NON_3GPP;
}

/**
 * @brief Priority-Based steering (TS 23.501 5.32.4)
 *
 * Uses the preferred access if available; falls back to the
 * alternative if the preferred path is down.
 *
 * @param cfg MAR configuration (priority_access)
 * @param state Access path state (liveness from probes)
 * @return Selected access type
 */
static __always_inline __u8
mar_steer_priority(struct mar_config* cfg, struct mar_access_state* state) {
  __u8 preferred = cfg->priority_access;
  __u8 fallback  = (preferred == ACCESS_3GPP) ? ACCESS_NON_3GPP : ACCESS_3GPP;

  if (preferred == ACCESS_3GPP && state->status_3gpp == PATH_STATUS_DOWN) {
    bpf_debug(
        "MAR: Priority -- preferred 3GPP DOWN, "
        "fallback to non-3GPP");
    return fallback;
  }

  if (preferred == ACCESS_NON_3GPP &&
      state->status_non3gpp == PATH_STATUS_DOWN) {
    bpf_debug(
        "MAR: Priority -- preferred non-3GPP DOWN, "
        "fallback to 3GPP");
    return fallback;
  }

  return preferred;
}

/* ========================================================================== */
/*                    ACCESS SELECTION DISPATCH */
/* ========================================================================== */

/**
 * @brief Select access path based on the configured steer mode
 *
 * Dispatches to the appropriate steering algorithm. Returns the
 * selected access type (3GPP or non-3GPP).
 *
 * For modes that require access state (RTT, liveness), looks up
 * mar_access_state_map. If no state is available, falls back to
 * the configured default access.
 *
 * @param seid PFCP session ID
 * @param cfg MAR configuration
 * @param pctx Packet context (5-tuple for load balancing)
 * @param now_ns Current timestamp
 * @return Selected access type (ACCESS_3GPP or ACCESS_NON_3GPP)
 */
static __always_inline __u8 mar_select_access(
    __u64 seid, struct mar_config* cfg, struct packet_context* pctx,
    __u64 now_ns) {
  struct mar_access_state* state;

  switch (cfg->steer_mode) {
    case STEER_ACTIVE_STANDBY:
      state = bpf_map_lookup_elem(&mar_access_state_map, &seid);
      if (!state) {
        bpf_debug("MAR: No access state -- using active access");
        return cfg->active_access;
      }
      return mar_steer_active_standby(cfg, state);

    case STEER_SMALLEST_DELAY:
      state = bpf_map_lookup_elem(&mar_access_state_map, &seid);
      if (!state) {
        bpf_debug("MAR: No RTT data -- defaulting to 3GPP");
        return ACCESS_3GPP;
      }
      return mar_steer_smallest_delay(state, now_ns);

    case STEER_LOAD_BALANCE:
      return mar_steer_load_balance(cfg, pctx);

    case STEER_PRIORITY_BASED:
      state = bpf_map_lookup_elem(&mar_access_state_map, &seid);
      if (!state) {
        bpf_debug("MAR: No access state -- using priority access");
        return cfg->priority_access;
      }
      return mar_steer_priority(cfg, state);

    default:
      bpf_debug(
          "MAR: Unknown steer mode %u -- defaulting to 3GPP", cfg->steer_mode);
      return ACCESS_3GPP;
  }
}

/* ========================================================================== */
/*                         MAR APPLICATION                                    */
/* ========================================================================== */

SEC("xdp")
int mar_apply(struct xdp_md* ctx) {
  bpf_debug("=== MAR Apply ===");

  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("Error: Failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  u64 seid = pctx->seid;

  /* ---------------------------------------------------------------- */
  /*  Uplink: access path already determined by incoming interface   */
  /* ---------------------------------------------------------------- */
  if (IS_UPLINK(pctx->session_type)) {
    bpf_debug(
        "MAR: UL -- access determined by ingress, "
        "SEID = %llu",
        seid);
    goto execute;
  }

  /* ---------------------------------------------------------------- */
  /*  Downlink: lookup MAR configuration (§8.2.123)                  */
  /*                                                                */
  /*  V17.10.0: pdr_match.c now propagates pdr->mar_id (§8.2.123)   */
  /*  into pctx->pdr_mar_id.  If 0, no MAR is associated with the   */
  /*  matched PDR (single-access session) — skip the map lookup.    */
  /* ---------------------------------------------------------------- */
  if (pctx->pdr_mar_id == 0) {
    bpf_debug(
        "MAR: pdr_mar_id=0 — no MAR for SEID=%llu, "
        "single-access session",
        seid);
    goto execute;
  }

  struct mar_config* cfg = bpf_map_lookup_elem(&mar_config_map, &seid);

  if (!cfg) {
    /*
     * No MAR entry for this SEID despite pdr_mar_id being non-zero.
     * Control plane inconsistency — fall through to default (3GPP) path.
     */
    bpf_debug(
        "MAR: No config for SEID=%llu (pdr_mar_id=%u) — "
        "CP inconsistency, using 3GPP path",
        seid, pctx->pdr_mar_id);
    goto execute;
  }

  bpf_debug(
      "MAR: MAR-ID=%u, steer_mode=%u, SEID=%llu (§8.2.123/§8.2.125)",
      cfg->mar_id, cfg->steer_mode, seid);

  /* ---------------------------------------------------------------- */
  /*  Select access path based on steer mode (8.2.76)                */
  /* ---------------------------------------------------------------- */
  __u64 now_ns = bpf_ktime_get_ns();

  __u8 selected_access = mar_select_access(seid, cfg, pctx, now_ns);

  bpf_debug(
      "MAR: Selected access = %s, SEID = %llu",
      selected_access == ACCESS_3GPP ? "3GPP/N3" : "non-3GPP/N9", seid);

  /* ---------------------------------------------------------------- */
  /*  Override redirect target if non-3GPP selected                  */
  /* ---------------------------------------------------------------- */
  if (selected_access == ACCESS_NON_3GPP) {
    /*
     * Redirect to N9 interface instead of N3.
     *
     * We perform the redirect directly here rather than through
     * EXECUTE_FINAL_ACTION, because the standard macro only knows
     * about N3 (DOWNLINK=1) and N6 (UPLINK=0) indices.
     *
     * redirect_interfaces_map[REDIRECT_N9] (index 2) must be
     * populated by userspace with the N9/N3IWF ifindex when
     * ATSSS is enabled for this deployment.
     */
    bpf_debug(
        "MAR: Redirecting DL to non-3GPP/N9 "
        "SEID = %llu",
        seid);

    __u32 n9_key = REDIRECT_N9;
    int ret      = bpf_redirect_map(&redirect_interfaces_map, n9_key, 0);

    return xdp_stats_record_action(ctx, ret);
  }

  /* 3GPP selected -- fall through to EXECUTE_FINAL_ACTION */
  bpf_debug(
      "MAR: Keeping 3GPP/N3 path "
      "SEID = %llu",
      seid);

execute:
  /*
   * MAR is the terminal node in the normal forwarding chain.
   * Execute the final XDP action determined by upstream programs.
   */
  EXECUTE_FINAL_ACTION(ctx, pctx);
}

char _license[] SEC("license") = "GPL";
