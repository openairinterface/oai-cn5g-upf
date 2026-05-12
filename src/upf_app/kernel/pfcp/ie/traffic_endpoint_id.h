/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_TRAFFIC_ENDPOINT_ID_H
#define _PFCP_TRAFFIC_ENDPOINT_ID_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct traffic_endpoint_id - Traffic Endpoint ID IE
 * @base: Common IE header
 * @traffic_endpoint_id: Traffic endpoint identifier (0-255)
 *
 * Identifies a traffic endpoint within a PDU session.
 */
struct traffic_endpoint_id {
  // struct ie_base base;
  __u8 traffic_endpoint_id;
} __attribute__((packed));

#endif /* _PFCP_TRAFFIC_ENDPOINT_ID_H */
