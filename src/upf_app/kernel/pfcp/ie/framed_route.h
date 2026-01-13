/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Framed-Route
 * Reference: 3GPP TS 29.244 Section 8.2.109
 */

#ifndef _PFCP_FRAMED_ROUTE_H
#define _PFCP_FRAMED_ROUTE_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct framed_route - Framed-Route IE
 * @base: Common IE header
 * @framed_route: IPv4 routing information (variable length)
 *
 * Contains IPv4 routing information for the UE.
 * Format as per RFC 2865 (RADIUS).
 */
struct framed_route {
  // struct ie_base base;
  char framed_route[PFCP_FRAMED_ROUTE_MAX_LEN];
} __attribute__((packed));

#endif /* _PFCP_FRAMED_ROUTE_H */
