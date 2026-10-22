/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#define KBUILD_MODNAME session_lookup_ip

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "custom_types.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"
#include "utils/types.h"

#include "pipeline_maps.h"
#include "framed_routing_bpf.h"
#include "tail_call_dispatcher.h"
#include "stats_maps.h"
#include "stats_types.h"

/* ========================================================================== */
/*                    FRAMED ROUTING FALLBACK (RFC 2865 Framed-Route)         */
/* ========================================================================== */

/**
 * @brief Resolve a downlink destination behind a UE to its owning session.
 *
 * For downlink traffic the destination IP is normally the UE's own address.
 * With Framed-Route (RFC 2865 / TS 29.061) the destination may instead be an
 * address inside a subnet routed *behind* the UE, which is not a key in
 * session_by_ue_ip_map. When framed routing is enabled we look the destination
 * prefix up in m_framed_route_mapping (populated by the control plane, keyed by
 * hash of the framed prefix) to recover the owning UE IP, then retry the
 * session lookup with that UE IP.
 *
 * Byte-order contract (host-order numeric throughout, matching pctx->ue_ip =
 * bpf_ntohl(daddr) and the userspace populate): the prefix mask/hash and the
 * stored UE IP are all host-order numeric.
 *
 * @param ue_ip_inout in: DL destination IP (host order); out: resolved UE IP
 * @return matching session, or NULL if not a framed destination
 */
static __always_inline struct session_id* resolve_framed_session(
    u32* ue_ip_inout) {
  u8 flag_key    = 0;
  u8* fr_enabled = bpf_map_lookup_elem(&framed_routing_flag, &flag_key);
  if (!fr_enabled || !*fr_enabled) return NULL;

  const u32 dst = *ue_ip_inout; /* host-order destination IP */

  /* Longest-prefix-first (/32 .. /1), mirroring the userspace insert order. */
#pragma clang loop unroll(full)
  for (int i = 0; i < 32; i++) {
    u32 cidr = 32 - i; /* 32 .. 1 — never 0, so the mask shift stays < 32 */

    struct FramedRoutingKeyBPF key = framed_routing_key_for_ip_cidr(dst, cidr);
    u32* real_ue_ip = bpf_map_lookup_elem(&m_framed_route_mapping, &key);
    if (!real_ue_ip) continue;

    struct session_id* s =
        bpf_map_lookup_elem(&session_by_ue_ip_map, real_ue_ip);
    if (s) {
      *ue_ip_inout = *real_ue_ip;
      return s;
    }
  }
  return NULL;
}

/* ========================================================================== */
/*                    PFCP SESSION LOOKUP (IP PDU)                            */
/* ========================================================================== */

/**
 * @brief Resolve UE IP to PFCP session and load rule flags
 *
 * Per TS 29.244 §5.2.1, the UPF uses the UE IP Address to identify
 * the PFCP session and its associated rules (PDR, FAR, QER, URR, BAR, MAR).
 *
 * @param ctx XDP context
 * @return XDP action via tail call or XDP_PASS if no session found
 */
SEC("xdp")
int session_lookup_ip(struct xdp_md* ctx) {
  bpf_debug("=== PFCP Session Lookup: IP PDU ===");

  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("Error: Failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  u32 ue_ip = pctx->ue_ip;

  /* Lookup PFCP session by UE IP Address (TS 29.244 §8.2.36) */
  struct session_id* session =
      bpf_map_lookup_elem(&session_by_ue_ip_map, &ue_ip);

  if (!session) {
    /* Not a UE address — try a Framed-Route destination behind a UE. */
    session = resolve_framed_session(&ue_ip);
    if (!session) {
      bpf_debug(
          "PFCP Session Lookup failed: no session for "
          "UE IP %pI4",
          &ue_ip);
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
    /* Rewrite ue_ip so the downstream PDR-match stage matches the owning
     * UE's PDR (its PDI UE IP), per the resolved framed route. */
    pctx->ue_ip = ue_ip;
    bpf_debug("Framed route resolved to UE IP %pI4", &ue_ip);
  }

  u64 seid    = session->seid;
  u32 teid_ul = bpf_htonl(session->teid_ul);
  u32 teid_dl = bpf_htonl(session->teid_dl);

  bpf_debug(
      "PFCP Session found: SEID = %llu, F-TEID (UL) = %u, "
      "F-TEID (DL) = %u",
      seid, teid_ul, teid_dl);

  /* Store session identifiers in packet context */
  pctx->seid    = seid;
  pctx->teid_ul = teid_ul;
  pctx->teid_dl = teid_dl;

  /*
   * Load per-session rule enable flags.
   *
   * Populated by control plane during PFCP Session Establishment
   * (TS 29.244 §7.2.2) or Modification (TS 29.244 §7.2.4).
   * If no entry exists, default to 0 (all rules disabled).
   */
  __u32* flags = bpf_map_lookup_elem(&session_rules_enabled_map, &seid);

  if (flags) {
    pctx->rules_enabled = *flags;
    bpf_debug(
        "Rules enabled: 0x%x: QER = %d, URR = %d", *flags,
        !!(*flags & RULE_QER_ENABLED), !!(*flags & RULE_URR_ENABLED));
    bpf_debug(
        "                     BAR = %d, MAR = %d",
        !!(*flags & RULE_BAR_ENABLED), !!(*flags & RULE_MAR_ENABLED));

  } else {
    pctx->rules_enabled = 0;
    bpf_debug("No rule flags for SEID = %llu — all rules disabled", seid);
  }

  /* Tail call: PDR Match */
  TAIL_CALL_NEXT(ctx, PROG_PDR_MATCH);

  bpf_debug("Error: Tail call to PROG_PDR_MATCH failed");
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
