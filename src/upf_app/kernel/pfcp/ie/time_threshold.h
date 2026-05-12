/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_TIME_THRESHOLD_H
#define _PFCP_TIME_THRESHOLD_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct time_threshold - Time Threshold IE
 * @time_threshold: Duration threshold (seconds)
 *
 * Specifies the time threshold for usage reporting.
 */
struct time_threshold {
  // struct ie_base base;
  __u32 time_threshold;
} __attribute__((packed));

#endif /* _PFCP_TIME_THRESHOLD_H */
