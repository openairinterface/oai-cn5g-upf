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
 * Changes:     Boy Scout cleanup — added Boy Scout header and section
 *              separators for consistency with xdp_* entry programs.
 *              Updated includes: removed unused pfcp_far/pfcp_pdr;
 *              upf_xdp_maps.h -> pipeline_maps.h (session_by_ue_ip_map);
 *              xdp_stats_kern.h -> stats_maps.h, xdp_stats_kern_user.h -> stats_types.h.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §7.2.2.1 — SEID
 *              3GPP TS 29.244 V17.10.0 §8.2.36  — UE IP Address IE
 *              3GPP TS 29.244 V17.10.0 §8.2.3   — F-TEID IE
 */
// clang-format on

/**
 * @file session_lookup_ip.c
 * @brief PFCP Session Lookup for IP PDU sessions
 *
 * Resolves UE IP Address to PFCP session context. Used by both uplink
 * and downlink paths (N3 and N6 entry points).
 *
 * Lookup: UE IP → session_by_ue_ip_map → {SEID, TEID_UL, TEID_DL}
 *
 * Also reads the per-session rule enable flags from
 * session_rules_enabled_map and caches them in pctx->rules_enabled
 * for use by all downstream programs.
 *
 * Chain: Entry → [SESSION_LOOKUP_IP] → PDR_MATCH → FAR → ...
 *
 * @see 3GPP TS 29.244 §7.2.2.1 - SEID
 * @see 3GPP TS 29.244 §8.2.36 - UE IP Address IE
 * @see 3GPP TS 29.244 §8.2.3 - F-TEID IE
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

#include "linux/custom_types.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"
#include "utils/types.h"

#include "pipeline_maps.h"
#include "tail_call_dispatcher.h"
#include "stats_maps.h"
#include "stats_types.h"

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
    bpf_debug(
        "PFCP Session Lookup failed: no session for "
        "UE IP %pI4",
        &ue_ip);
    return xdp_stats_record_action(ctx, XDP_PASS);
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
