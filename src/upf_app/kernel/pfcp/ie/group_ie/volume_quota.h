/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_VOLUME_QUOTA_H
#define _PFCP_VOLUME_QUOTA_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct volume_quota - Volume Quota IE
 * @total_volume: Total volume quota (bytes)
 * @uplink_volume: Uplink volume quota (bytes)
 * @downlink_volume: Downlink volume quota (bytes)
 *
 * Volume-based usage quota for Usage Reporting Rules.
 * Packets are dropped when quota is exhausted.
 */
struct volume_quota {
  // struct ie_base base;
  __u64 total_volume;
  __u64 uplink_volume;
  __u64 downlink_volume;
} __attribute__((packed));

#endif /* _PFCP_VOLUME_QUOTA_H */
