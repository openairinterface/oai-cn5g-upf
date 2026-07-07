/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_VOLUME_THRESHOLD_H
#define _PFCP_VOLUME_THRESHOLD_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct volume_threshold - Volume Threshold IE
 * @total_volume: Total volume threshold (bytes)
 * @uplink_volume: Uplink volume threshold (bytes)
 * @downlink_volume: Downlink volume threshold (bytes)
 *
 * Volume-based reporting threshold for Usage Reporting Rules.
 */
struct volume_threshold {
  // struct ie_base base;
  __u64 total_volume;
  __u64 uplink_volume;
  __u64 downlink_volume;
} __attribute__((packed));

#endif /* _PFCP_VOLUME_THRESHOLD_H */
