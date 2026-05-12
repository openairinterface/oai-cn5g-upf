/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_ACCESS_FORWARDING_ACTION_INFO_H
#define _PFCP_ACCESS_FORWARDING_ACTION_INFO_H

#include <linux/types.h>
#include "ie/far_id.h"

/**
 * struct access_forwarding_action_info - Access Forwarding Action Information
 * @far_id: FAR ID for this access type
 * @urr_id: URR ID for per-access usage reporting
 * @priority: Forwarding priority (0-255)
 * @weight: Load balancing weight (0-255)
 *
 * Per-access forwarding configuration within a MAR.
 * Info 1 = 3GPP access, Info 2 = non-3GPP access.
 */
struct access_forwarding_action_info {
  struct far_id far_id;
  __u32 urr_id;
  __u8 priority;
  __u8 weight;
  __u8 pad[2];
} __attribute__((packed));

#endif /* _PFCP_ACCESS_FORWARDING_ACTION_INFO_H */
