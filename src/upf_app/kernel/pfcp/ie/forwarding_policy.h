/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Forwarding Policy
 * Reference: 3GPP TS 29.244 Section 8.2.23
 */

#ifndef _PFCP_FORWARDING_POLICY_H
#define _PFCP_FORWARDING_POLICY_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct forwarding_policy - Forwarding Policy IE
 * @base: Common IE header
 * @forwarding_policy_id_len: Length of policy identifier
 * @forwarding_policy_id: Forwarding policy identifier string
 *
 * Identifies a forwarding policy to be applied to matching traffic.
 */
struct forwarding_policy {
  // struct ie_base base;
  __u8 forwarding_policy_id_len;
  char forwarding_policy_id[PFCP_FORWARDING_POLICY_ID_MAX_LEN];
} __attribute__((packed));

#endif /* _PFCP_FORWARDING_POLICY_H */
