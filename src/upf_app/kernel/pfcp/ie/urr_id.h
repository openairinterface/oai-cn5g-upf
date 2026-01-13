/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP URR ID
 * Reference: 3GPP TS 29.244 Section 8.2.55
 */

#ifndef _PFCP_URR_ID_H
#define _PFCP_URR_ID_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct urr_id - Usage Reporting Rule ID
 * @base: Common IE header
 * @urr_id: URR identifier (network byte order)
 *
 * Uniquely identifies a Usage Reporting Rule within a PFCP session.
 * Used for charging and usage monitoring.
 */
struct urr_id {
  // struct ie_base base;
  __u32 urr_id;
} __attribute__((packed));

#endif /* _PFCP_URR_ID_H */
