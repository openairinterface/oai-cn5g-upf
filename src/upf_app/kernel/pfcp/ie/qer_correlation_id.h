/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP QER Correlation ID
 * Reference: 3GPP TS 29.244 Section 8.2.10
 */

#ifndef _PFCP_QER_CORRELATION_ID_H
#define _PFCP_QER_CORRELATION_ID_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct qer_correlation_id - QER Correlation ID IE
 * @base: Common IE header
 * @qer_correlation_id: Correlation ID (network byte order)
 *
 * Correlates QERs across different PFCP sessions or nodes.
 */
struct qer_correlation_id {
  // struct ie_base base;
  __u32 qer_correlation_id;
} __attribute__((packed));

#endif /* _PFCP_QER_CORRELATION_ID_H */
