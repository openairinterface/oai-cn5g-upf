/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_MONITORING_TIME_H
#define _PFCP_MONITORING_TIME_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct monitoring_time - Monitoring Time IE
 * @monitoring_time: Measurement start timestamp (NTP epoch, seconds)
 *
 * Specifies the start time for usage measurement.
 */
struct monitoring_time {
  // struct ie_base base;
  __u32 monitoring_time;
} __attribute__((packed));

#endif /* _PFCP_MONITORING_TIME_H */
