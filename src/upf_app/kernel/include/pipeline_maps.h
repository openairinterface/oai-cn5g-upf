/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __PIPELINE_MAPS_H__
#define __PIPELINE_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "pipeline_types.h"
#include "sdf_types.h"
#include "upf_xdp_limits.h"
#include "pfcp/pfcp_pdr.h"
#include "pfcp/pfcp_far.h"
#include "upf_map_limits.h"

/* ==========================================================================
 * session_by_ue_ip_map
 * ========================================================================== */

/**
 * @brief UE IP address -> PFCP session lookup (IP PDU downlink path).
 *
 * Key:   u32                UE IPv4 address (network byte order)
 * Value: struct session_id  {teid_ul, teid_dl, seid}
 * Size:  MAX_PDU_SESSIONS
 *
 * Written by SessionProgramManager on session establishment.
 * Read by session_lookup_ip.c on every N6 downlink packet.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u32);
  __type(value, struct session_id);
} session_by_ue_ip_map SEC(".maps");

/* ==========================================================================
 * pdrs_per_session_map
 * ========================================================================== */

/**
 * @brief Per-session PDR array.
 *
 * Key:   u64                             SEID
 * Value: struct pfcp_pdr[MAX_PDRS_PER_PDU_SESSION_LIMIT]
 * Size:  MAX_PDU_SESSIONS
 *
 * Each value is an array of PDRs for the session, sorted by precedence.
 * pdr_match.c iterates the array to find the highest-precedence match.
 *
 * NOTE: Map size = number of sessions, NOT total PDR count.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u64);
  __type(value, struct pfcp_pdr[MAX_PDRS_PER_PDU_SESSION_LIMIT]);
} pdrs_per_session_map SEC(".maps");

/* ==========================================================================
 * session_qos_enabled_map
 * ========================================================================== */

/**
 * @brief Per-session QoS enable flag (legacy compatibility map).
 *
 * Key:   u64   SEID
 * Value: u32   0 = QoS disabled, 1 = QoS enabled
 * Size:  MAX_PDU_SESSIONS
 *
 * Kept for backward compatibility with older userspace versions.
 * New code should use session_rules_enabled_map (in tail_call_maps.h).
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u64);
  __type(value, u32);
} session_qos_enabled_map SEC(".maps");

/* ==========================================================================
 * rules_match_pdr_map
 * ========================================================================== */

/**
 * @brief PDR -> full rule set lookup table.
 *
 * Key:   struct pdrs_per_session  {pdr_id, seid}
 * Value: struct rules_match_pdr   {far, qer, urr, bar, mar}
 * Size:  MAX_PDU_SESSIONS x MAX_PDRS_PER_PDU_SESSION
 *
 * Written by SessionProgramManager on session establishment/modification.
 * Read by pdr_match.c after PDR precedence selection to hand the full
 * rule set to downstream tail-call programs.
 *
 * Example: 1000 sessions x 16 PDRs = 16 000 entries.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(
      max_entries,
      1); /* Runtime: MAX_PDU_SESSIONS x MAX_PDRS_PER_PDU_SESSION */
  __type(key, struct pdrs_per_session);
  __type(value, struct rules_match_pdr);
} rules_match_pdr_map SEC(".maps");

/* ==========================================================================
 * m_framed_route_mapping
 * ========================================================================== */

/**
 * @brief Framed route hash -> UE IP mapping.
 *
 * Key:   u32   hash of framed routing key (prefix + metric)
 * Value: u32   UE IPv4 address
 * Size:  MAX_PDU_SESSIONS
 *
 * Used when framed_routing_flag is set to route packets destined for
 * UE-assigned prefixes (RFC 2865 Framed-Route attribute).
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u32);
  __type(value, u32);
} m_framed_route_mapping SEC(".maps");

/* ==========================================================================
 * framed_routing_flag
 * ========================================================================== */

/**
 * @brief Global framed routing enable flag.
 *
 * Key:   u8   always 0
 * Value: u8   0 = disabled, 1 = enabled
 * Size:  1
 *
 * Set by userspace configuration. When 1, pdr_match.c performs an
 * additional lookup in m_framed_route_mapping for unmatched packets.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, u8);
  __type(value, u8);
} framed_routing_flag SEC(".maps");

/* ==========================================================================
 * feature_dispatch_map
 * ========================================================================== */

/**
 * @brief BPF PROG_ARRAY for feature tail-call dispatch.
 *
 * Key:   u32   program index (enum tail_call_prog_index)
 * Value: u32   BPF program file descriptor
 * Size:  MAX_TAIL_CALL_PROGS (16)
 *
 * Loaded by userspace with the FD of each pipeline stage program.
 * Used by TAIL_CALL_NEXT() macro in tail_call_dispatch.h.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, MAX_TAIL_CALL_PROGS);
  __type(key, u32);
  __type(value, u32);
} feature_dispatch_map SEC(".maps");

#endif /* __PIPELINE_MAPS_H__ */