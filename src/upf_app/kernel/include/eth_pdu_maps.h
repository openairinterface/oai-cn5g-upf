/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __ETH_PDU_MAPS_H__
#define __ETH_PDU_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "eth_pdu_types.h"
#include "upf_xdp_limits.h"
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
