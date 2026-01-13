/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP QER ID
 * Reference: 3GPP TS 29.244 Section 8.2.75
 */

#ifndef _PFCP_QER_ID_H
#define _PFCP_QER_ID_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct qer_id - QoS Enforcement Rule ID
 * @base: Common IE header
 * @qer_id: QER identifier (network byte order)
 *
 * Uniquely identifies a QoS Enforcement Rule within a PFCP session.
 */
struct qer_id {
  // struct ie_base base;
  __u32 qer_id;
} __attribute__((packed));

#endif /* _PFCP_QER_ID_H */
