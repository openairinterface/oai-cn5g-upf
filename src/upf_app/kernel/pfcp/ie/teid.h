/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_TEID_H
#define _PFCP_TEID_H

#include <linux/types.h>

/**
 * teid_t - Tunnel Endpoint Identifier
 *
 * 32-bit identifier used in GTP-U tunnels to multiplex connections.
 * Network byte order.
 */
typedef __u32 teid_t;
#define TEID_FMT "0x%" PRIx32
#define TEID_SCAN_FMT SCNx32
// #define INVALID_TEID             ((teid_t)0x00000000)
// #define UNASSIGNED_TEID          ((teid_t)0x00000000)

#endif  // IE_TEID_H
