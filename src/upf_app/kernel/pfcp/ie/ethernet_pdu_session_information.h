/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Ethernet PDU Session Information
 * Reference: 3GPP TS 29.244 Section 8.2.102
 */

#ifndef _PFCP_ETHERNET_PDU_SESSION_INFORMATION_H
#define _PFCP_ETHERNET_PDU_SESSION_INFORMATION_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct ethernet_pdu_session_information - Ethernet PDU Session Info IE
 * @base: Common IE header
 * @ethi: Ethernet indication flag
 * @spare: Spare bits
 *
 * Indicates if the PDU session is for Ethernet PDUs.
 *
 * Bit layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |          spare           |ethi|
 * +---+---+---+---+---+---+---+---+
 */
struct ethernet_pdu_session_information {
  // struct ie_base base;
  __u8 spare : 7, ethi : 1;
} __attribute__((packed));
;

#endif /* _PFCP_ETHERNET_PDU_SESSION_INFORMATION_H */
