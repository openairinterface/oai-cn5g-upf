/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __ETH_SESSION_MAPS_H__
#define __ETH_SESSION_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "eth_pdu_types.h"

/* ==========================================================================
 * eth_session_mapping_map
 * ========================================================================== */

/**
 * @brief Uplink TEID -> ETH session context.
 *
 * Key:   u32                     uplink GTP-U TEID (host byte order
 *                                 matches pctx->pkt_teid on the IP PDU path)
 * Value: struct eth_session_id  {teid_ul, teid_dl, ipv4_address, qfi_dl,
 *                                 seid}
 * Size:  MAX_PDU_SESSIONS
 *
 * Populated by SessionProgramManager during PFCP Session Establishment.
 * Read by xdp_n3_eth_entry.c, which classifies a G-PDU as ETH PDU when its
 * TEID is here, and by session_lookup_eth.c to resolve the SEID.
 *
 * Kept apart from eth_pdu_maps.h so xdp_n3_eth_entry can declare (and own)
 * this map alone.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u32);
  __type(value, struct eth_session_id);
} eth_session_mapping_map SEC(".maps");

#endif /* __ETH_SESSION_MAPS_H__ */
