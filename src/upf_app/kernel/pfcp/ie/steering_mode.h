/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_STEERING_MODE_H
#define _PFCP_STEERING_MODE_H

#include <linux/types.h>
#include "ie_base.h"

#define STEER_MODE_ACTIVE_STANDBY  0  /* Active-Standby */
#define STEER_MODE_SMALLEST_DELAY  1  /* Smallest Delay */
#define STEER_MODE_LOAD_BALANCE    2  /* Load Balancing */
#define STEER_MODE_PRIORITY_BASED  3  /* Priority-Based */

/**
 * struct steering_mode - Steering Mode IE
 * @steer_mode_value: STEER_MODE_* enum
 *
 * Indicates the ATSSS steering mode for multi-access traffic.
 */
struct steering_mode {
  // struct ie_base base;
  __u8 steer_mode_value;
} __attribute__((packed));

#endif /* _PFCP_STEERING_MODE_H */
