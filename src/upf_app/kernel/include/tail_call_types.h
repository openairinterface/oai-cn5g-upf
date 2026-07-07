/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __TAIL_CALL_TYPES_H__
#define __TAIL_CALL_TYPES_H__

#include "linux/custom_types.h"
#include "packet_context.h"

/* ==========================================================================
 * PROG_ARRAY slot indices
 * ========================================================================== */

/**
 * @brief Program indices into tail_call_progs_map (BPF_MAP_TYPE_PROG_ARRAY).
 *
 * Used as the key in:
 *   bpf_tail_call(ctx, &tail_call_progs_map, PROG_<NAME>);
 *
 * The userspace loader (xdp_upf_user.cpp) populates the corresponding
 * slots based on the feature flags in the YAML configuration.
 * Slots for disabled features are left empty.
 *
 * NOTE: IP and ETH session lookup occupy distinct slots (0 and 1)
 * because entry points choose which lookup to call based on the PDU
 * session type detected from the incoming packet.
 */
enum upf_prog_index {
  PROG_SESSION_LOOKUP_IP  = 0, /**< Always present -- IP PDU session lookup  */
  PROG_SESSION_LOOKUP_ETH = 1, /**< Always present -- ETH PDU session lookup */
  PROG_PDR_MATCH          = 2, /**< Always present -- PDR matching           */
  PROG_FAR_APPLY          = 3, /**< Always present -- forwarding action      */
  PROG_QER_APPLY          = 4, /**< enable_qer: yes -- QoS enforcement       */
  PROG_URR_APPLY          = 5, /**< enable_urr: yes -- usage reporting       */
  PROG_BAR_APPLY          = 6, /**< enable_bar: yes -- buffering action      */
  PROG_MAR_APPLY          = 7, /**< enable_mar: yes -- multi-access routing  */
  PROG_MAX                = 8, /**< Sentinel -- must equal number of entries */
};

/* ==========================================================================
 * Per-session feature flags
 * ========================================================================== */

/**
 * @brief Per-session feature enable flags stored in session_rules_enabled_map.
 *
 * Written by SessionProgramManager on session establishment and updated
 * on modification. Read by xdp_far_apply.c and subsequent stages to
 * decide whether to tail-call the next optional stage or skip it.
 */
struct session_rule_flags {
  u8 qer_enabled; /**< 1 if this session has an active QER rule */
  u8 urr_enabled; /**< 1 if this session has an active URR rule */
  u8 bar_enabled; /**< 1 if this session has an active BAR rule */
  u8 mar_enabled; /**< 1 if this session has an active MAR rule */
};

#endif /* __TAIL_CALL_TYPES_H__ */