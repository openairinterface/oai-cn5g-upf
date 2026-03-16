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
 * Changes:     V17.10.0 reference — averaging_window field noted in TODO:
 *                - pfcp_qer.h now carries averaging_window (§8.2.134).
 *                  When MBR/GBR enforcement is implemented the averaging
 *                  window must be used to smooth GBR token-bucket refills
 *                  for 5G NR burst tolerance per TS 29.244 §8.2.134.
 *              Boy Scout cleanup:
 *                - §8.2.41 / §8.2.42 / §8.2.43 comment refs verified
 *                  against V17.10.0.
 *                - Replaced bare @file block with changelog + guards.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §8.2.40   QER ID            §8.2.41  Gate Status
 *              §8.2.42   MBR               §8.2.43  GBR
 *              §8.2.134  Averaging Window (V17.10.0 addition)
 */
// clang-format on

/**
 * @file qer_apply.c
 * @brief QER (QoS Enforcement Rule) — gate check and TC metadata writer
 *
 * Only reached when RULE_QER_ENABLED is set in pctx->rules_enabled.
 *
 * Responsibilities:
 *   1. Lookup QER associated with matched PDR (via rules_match_pdr_map)
 *   2. Check Gate Status IE (TS 29.244 §8.2.41):
 *      - DL-Gate / UL-Gate: OPEN (0) or CLOSED (non-zero)
 *      - If gate CLOSED → override final_action to DROP
 *   3. Write SEID + QFI to XDP metadata for TC QoS shaping (DL only)
 *
 * Chain: ... → FAR → [QER_APPLY] → [URR] → [MAR] → execute
 *
 * @see 3GPP TS 29.244 §8.2.40 - QER ID
 * @see 3GPP TS 29.244 §8.2.41 - Gate Status (UL/DL)
 * @see 3GPP TS 29.244 §8.2.42 - Maximum Bit Rate (MBR)
 * @see 3GPP TS 29.244 §8.2.43 - Guaranteed Bit Rate (GBR)
 */

#define KBUILD_MODNAME qer_apply

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
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

#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_pdr.h"

#include "upf_xdp_maps.h"
#include "interfaces.h"
#include "sdf_filter.h"
#include "tail_call_dispatch.h"
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

/* ========================================================================== */
/*                         QER APPLICATION                                    */
/* ========================================================================== */

SEC("xdp")
int qer_apply(struct xdp_md* ctx) {
  bpf_debug("=== QER Apply ===");

  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("Error: Failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  u64 seid    = pctx->seid;
  u32 pdr_id  = pctx->pdr_id;
  u8 qfi      = pctx->qfi;
  __u32 flags = pctx->rules_enabled;

  /* Lookup rules associated with this PDR to get QER */
  struct pdrs_per_session pdr_key = {0};

  pdr_key.pdr_id = pdr_id;
  pdr_key.seid   = seid;

  struct rules_match_pdr* rules =
      bpf_map_lookup_elem(&rules_match_pdr_map, &pdr_key);

  if (!rules) {
    bpf_debug("QER: No rules for PDR (SEID=%llu)", seid);
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  struct pfcp_qer* qer = &rules->qer;

  /* -------------------------------------------------------------- */
  /*  Gate Status IE (TS 29.244 §8.2.41)                            */
  /*                                                                */
  /*  Gate Status encoding per R16:                                 */
  /*    0 = OPEN   - traffic shall pass                             */
  /*    1 = CLOSED - traffic shall be dropped                       */
  /* -------------------------------------------------------------- */

  if (IS_DOWNLINK(pctx->session_type)) {
    if (qer->gate_status.dl_gate != 0) {
      bpf_debug(
          "Gate Status: DL-Gate = CLOSED "
          "SEID = %llu, QFI = %u - DROP",
          seid, qer->qos_flow_identifier.qfi);
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    bpf_debug(
        "Gate Status: DL-Gate = OPEN "
        "SEID = %llu, QFI = %u",
        seid, qer->qos_flow_identifier.qfi);
  } else {
    if (qer->gate_status.ul_gate != 0) {
      bpf_debug(
          "Gate Status: UL-Gate = CLOSED "
          "SEID = %llu, QFI = %u - DROP",
          seid, qer->qos_flow_identifier.qfi);
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    bpf_debug(
        "Gate Status: UL-Gate = OPEN "
        "SEID = %llu, QFI = %u",
        seid, qer->qos_flow_identifier.qfi);
  }

  /* -------------------------------------------------------------- */
  /*  Write QoS metadata for TC layer (DL only)                     */
  /*  N6 entry already reserved space with bpf_xdp_adjust_meta()    */
  /* -------------------------------------------------------------- */

  if (IS_DOWNLINK(pctx->session_type)) {
    void* data = (void*) (long) ctx->data;
    struct session_qfi* qos_metadata =
        (struct session_qfi*) (long) ctx->data_meta;

    if ((void*) (qos_metadata + 1) > data) {
      bpf_debug("Error: Invalid XDP metadata pointer");
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    qos_metadata->seid = seid;
    qos_metadata->qfi  = qfi;
    bpf_debug("QoS metadata: SEID = %llu, QFI = %u → TC", seid, qfi);
  }

  /* -------------------------------------------------------------- */
  /*  TODO: Rate enforcement — MBR/GBR (§8.2.42-43)                 */
  /*                                                                */
  /*  Per TS 29.244 §8.2.42 (Maximum Bit Rate):                     */
  /*    - Token bucket or leaky bucket algorithm                    */
  /*    - Separate UL/DL MBR per QER                                */
  /*                                                                */
  /*  Per TS 29.244 §8.2.43 (Guaranteed Bit Rate):                  */
  /*    - Requires scheduling cooperation with TC layer             */
  /*                                                                */
  /*  V17.10.0: §8.2.134 Averaging Window must be used when present */
  /*  to set the smoothing interval for GBR token-bucket refill.    */
  /*  qer->averaging_window.averaging_window carries the value in   */
  /*  milliseconds; 0 means not configured.                         */
  /*                                                                */
  /*  Implementation options:                                       */
  /*    1. Per-flow byte counters + time-based token refill in BPF  */
  /*    2. Delegate to TC HTB classes (current via tc_classid)      */
  /*    3. Hybrid: XDP gate check, TC rate shaping                  */
  /* -------------------------------------------------------------- */

  /* Dispatch to next enabled program: [URR] → [MAR] → execute */
  dispatch_after_qer(ctx, flags);

  /* All downstream disabled or tail call failed — execute now */
  bpf_debug("QER: Executing final action (no downstream rules)");
  EXECUTE_FINAL_ACTION(ctx, pctx);
}

char _license[] SEC("license") = "GPL";
