/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __ETH_PDU_MAPS_H__
#define __ETH_PDU_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "eth_pdu_types.h"
#include "pipeline_types.h"
#include "upf_xdp_limits.h"
#include "pfcp/pfcp_pdr.h"
#include "pfcp/pfcp_far.h"
#include "upf_map_limits.h"

/* ==========================================================================
 * session_by_mac_map
 * ========================================================================== */

/**
 * @brief UE MAC address -> session_id lookup (ETH PDU downlink path).
 *
 * Key:   __u8[6]   UE Ethernet MAC address
 * Value: __u32     session_id (SEID lower 32 bits, fast DL lookup)
 * Size:  MAX_PDU_SESSIONS
 *
 * Populated by SessionProgramManager for Ethernet PDU sessions.
 * Read by session_lookup_eth.c to find the session for a DL frame.
 *
 * 3GPP Ref: TS 29.244 §5.8.2 — Ethernet PDU sessions
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, __u8[6]);
  __type(value, __u32);
} session_by_mac_map SEC(".maps");

/* ==========================================================================
 * eth_session_mapping_map
 * ========================================================================== */

/**
 * @brief Uplink TEID -> ETH session context.
 *
 * Key:   u32                     uplink GTP-U TEID (host byte order
 *                                 matches pctx->pkt_teid on the IP PDU path)
 * Value: struct eth_session_id  {teid_ul, teid_dl, ipv4_address, seid}
 * Size:  MAX_PDU_SESSIONS
 *
 * Populated by SessionProgramManager during PFCP Session Establishment.
 * Read by xdp_n3_eth_entry.c and session_lookup_eth.c to resolve the SEID
 * from the GTP-U TEID on incoming uplink packets.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u32);
  __type(value, struct eth_session_id);
} eth_session_mapping_map SEC(".maps");

/* ==========================================================================
 * eth_session_pdrs_map
 * ========================================================================== */

/**
 * @brief Per-session PDR array for Ethernet PDU sessions.
 *
 * Key:   u64                                   SEID
 * Value: struct pfcp_pdr[MAX_PDRS_PER_ETH_PDU_SESSION_LIMIT]  PDR array,
 *        sorted by precedence
 * Size:  MAX_PDU_SESSIONS
 *
 * ETH-PDU-path mirror of pdrs_per_session_map.
 * Kept separate because this is compiled as a distinct BPF object.
 * Read by match_pdr_eth_n3() (xdp_pdr_match_kern.c) to find the
 * highest-precedence match.
 *
 * NOTE: Map size = number of sessions, NOT total PDR count.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u64);
  __type(value, struct pfcp_pdr[MAX_PDRS_PER_ETH_PDU_SESSION_LIMIT]);
} eth_session_pdrs_map SEC(".maps");

/* ==========================================================================
 * eth_rules_match_pdr_map
 * ========================================================================== */

/**
 * @brief PDR -> full rule set for Ethernet PDU sessions.
 *
 * Key:   struct pdrs_per_session  {pdr_id, seid}
 * Value: struct rules_match_pdr   {far, qer, urr, bar, mar}
 * Size:  MAX_PDU_SESSIONS x MAX_PDRS_PER_PDU_SESSION
 *
 * ETH-PDU-path mirror of rules_match_pdr_map.
 * Populated by SessionProgramManager for sessions with Ethernet PDU type.
 * Read by the ETH pipeline stages to apply the matched rule set.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(
      max_entries,
      1); /* Runtime: MAX_PDU_SESSIONS x MAX_PDRS_PER_PDU_SESSION */
  __type(key, struct pdrs_per_session);
  __type(value, struct rules_match_pdr);
} eth_rules_match_pdr_map SEC(".maps");

/* ==========================================================================
 * eth_egress_ifindex_map
 * ========================================================================== */

/**
 * @brief Egress interface DEVMAP for Ethernet PDU XDP_REDIRECT.
 *
 * Key:   u32   interface slot index (0 .. MAX_UPF_INTERFACES-1)
 * Value: u32   kernel ifindex of the egress network device
 * Size:  MAX_UPF_INTERFACES (10)
 *
 * Populated by xdp_upf_user.cpp using if_nametoindex().
 * Used by xdp_n6_eth_entry.c to redirect Ethernet frames to the
 * correct egress interface via XDP_REDIRECT.
 */
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 1); /*MAX_UPF_REDIRECT_INTERFACES*/
  __type(key, u32);
  __type(value, u32);
} eth_egress_ifindex_map SEC(".maps");

/* ==========================================================================
 * mac_pdu_session_map
 * ========================================================================== */

/**
 * @brief MAC learning table: inner src MAC -> DL tunnel parameters.
 *
 * Key:   u8[ETH_ALEN]               inner Ethernet source MAC address
 * Value: struct mac_pdu_session_value  {teid (DL, network byte order),
 *                                       ipv4_address (gNB, network byte order)}
 * Size:  MAX_UEs (set at runtime)
 *
 * Written by xdp_session_lookup_eth.c on every uplink packet (BPF_ANY) to
 * record the latest gNB association for this UE MAC (handles handover).
 * Read by xdp_n6_eth_entry.c to encapsulate downlink frames for known MACs.
 *
 * NOTE: distinct from session_by_mac_map (MAC -> session_id scalar used for
 * downlink session lookup). This map carries the full DL tunnel parameters.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_UEs or max_pdu_sessions */
  __type(key, u8[ETH_ALEN]);
  __type(value, struct mac_pdu_session_value);
} mac_pdu_session_map SEC(".maps");

#endif /* __ETH_PDU_MAPS_H__ */
