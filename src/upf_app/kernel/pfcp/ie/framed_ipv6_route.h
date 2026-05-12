/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_FRAMED_IPV6_ROUTE_H
#define _PFCP_FRAMED_IPV6_ROUTE_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct framed_ipv6_route - Framed-IPv6-Route IE
 * @base: Common IE header
 * @framed_ipv6_route: IPv6 routing information (variable length)
 *
 * Contains IPv6 routing information for the UE.
 * Format as per RFC 3162 (RADIUS IPv6).
 */
struct framed_ipv6_route {
  // struct ie_base base;
  char framed_ipv6_route[PFCP_FRAMED_IPV6_ROUTE_MAX_LEN];
} __attribute__((packed));

#endif /* _PFCP_FRAMED_IPV6_ROUTE_H */
