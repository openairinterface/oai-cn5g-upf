/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_APPLICATION_ID_H
#define _PFCP_APPLICATION_ID_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct application_id - Application ID IE
 * @base: Common IE header
 * @application_id: Application identifier string
 *
 * Identifies an application for traffic detection and policy control.
 * Variable length string (e.g., "facebook", "youtube").
 */
struct application_id {
  // struct ie_base base;
  char application_id[PFCP_APPLICATION_ID_MAX_LEN];
} __attribute__((packed));

#endif /* _PFCP_APPLICATION_ID_H */
