/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Framed-Routing
 * Reference: 3GPP TS 29.244 Section 8.2.110
 */

#ifndef _PFCP_FRAMED_ROUTING_H
#define _PFCP_FRAMED_ROUTING_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct framed_routing - Framed-Routing IE
 * @base: Common IE header
 * @framed_routing: Routing method (network byte order)
 *
 * Specifies the routing method for the UE.
 * As per RFC 2865 (RADIUS).
 */
struct framed_routing {
  // struct ie_base base;
  __u32 framed_routing;
} __attribute__((packed));

#endif /* _PFCP_FRAMED_ROUTING_H */
