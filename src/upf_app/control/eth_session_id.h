/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __ETH_SESSION_ID_H__
#define __ETH_SESSION_ID_H__

#include "custom_types.h"

/** @brief BPF map value for an Ethernet PDU session (key: uplink TEID).
 *
 *  Stored in eth_session_mapping_map.  Unlike IP PDU sessions keyed by UE IP
 *  (session_by_ue_ip_map), Ethernet PDU sessions use the uplink TEID as the
 *  primary lookup key since there is no routable UE IP in the payload.
 *
 *  @see 3GPP TS 23.501 §5.6.10.3 — Ethernet PDU Session Type
 *  @see 3GPP TS 29.281 §5.1      — GTP-U TEID allocation
 *  @see 3GPP TS 29.244 §8.2.37   — F-SEID / SEID
 */
struct eth_session_id {
  u32 teid_ul;       ///< Uplink TEID   — UPF listens on N3 (TS 29.281 §5.1)
  u32 teid_dl;       ///< Downlink TEID — GTP-U encapsulation toward gNB
  u32 ipv4_address;  ///< gNB outer IP  — outer header creation destination
  u64 seid;  ///< PFCP SEID     — Session Endpoint Identifier (§8.2.37)
};

#endif /* __ETH_SESSION_ID_H__ */
