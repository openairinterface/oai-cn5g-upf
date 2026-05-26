/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Transport Level Marking
 * Reference: 3GPP TS 29.244 Section 8.2.12
 */

#ifndef _PFCP_TRANSPORT_LEVEL_MARKING_H
#define _PFCP_TRANSPORT_LEVEL_MARKING_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct transport_level_marking - Transport Level Marking IE
 * @base: Common IE header
 * @tos_traffic_class: ToS/Traffic Class value and mask (2 octets)
 *
 * ToS (IPv4) or Traffic Class (IPv6) value for QoS marking.
 * Octet 0: value, Octet 1: mask
 */
struct transport_level_marking {
  // struct ie_base base;
  __u8 tos_traffic_class[2];
} __attribute__((packed));

#endif /* _PFCP_TRANSPORT_LEVEL_MARKING_H */
