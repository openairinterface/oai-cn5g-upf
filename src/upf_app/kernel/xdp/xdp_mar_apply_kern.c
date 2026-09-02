/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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

#include "custom_types.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"
#include "utils/types.h"

#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_pdr.h"

#include "pipeline_maps.h"
#include "mar_maps.h"
#include "interfaces_types.h"
#include "interfaces_maps.h" /* declares redirect_interfaces_map (used below) */
#include "tail_call_dispatcher.h"
#include "stats_types.h"
#include "stats_maps.h"

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
