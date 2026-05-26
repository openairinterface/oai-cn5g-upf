/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Network Instance
 * Reference: 3GPP TS 29.244 Section 8.2.4
 */

#ifndef _PFCP_NETWORK_INSTANCE_H
#define _PFCP_NETWORK_INSTANCE_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct network_instance - Network Instance IE
 * @base: Common IE header
 * @network_instance: Network instance name (APN/DNN format)
 *
 * Identifies the PDN/Data Network (e.g., "internet", "ims").
 */
struct network_instance {
  // struct ie_base base;
  char network_instance[PFCP_NETWORK_INSTANCE_MAX_LEN];
} __attribute__((packed));
;

#endif /* _PFCP_NETWORK_INSTANCE_H */
