/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_STEERING_FUNCTIONALITY_H
#define _PFCP_STEERING_FUNCTIONALITY_H

#include <linux/types.h>
#include "ie_base.h"

#define STEERING_FUNC_ATSSS_LL 0 /* ATSSS Low Layer */
#define STEERING_FUNC_MPTCP 1    /* MPTCP           */

/**
 * struct steering_functionality - Steering Functionality IE
 * @steering_functionality_value: STEERING_FUNC_* enum
 *
 * Indicates ATSSS-LL or MPTCP steering functionality.
 */
struct steering_functionality {
  // struct ie_base base;
  __u8 steering_functionality_value;
} __attribute__((packed));

#endif /* _PFCP_STEERING_FUNCTIONALITY_H */
