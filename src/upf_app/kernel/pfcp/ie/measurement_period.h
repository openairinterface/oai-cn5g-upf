/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_MEASUREMENT_PERIOD_H
#define _PFCP_MEASUREMENT_PERIOD_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct measurement_period - Measurement Period IE
 * @measurement_period: Periodic reporting interval (seconds)
 *
 * Specifies the interval for periodic usage reporting.
 */
struct measurement_period {
  // struct ie_base base;
  __u32 measurement_period;
} __attribute__((packed));

#endif /* _PFCP_MEASUREMENT_PERIOD_H */
