/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_IE_TIME_QUOTA_H
#define _PFCP_IE_TIME_QUOTA_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct time_quota - Time Quota IE
 * @time_quota: Maximum duration (in seconds, big-endian) allowed for a
 *              URR-monitored service data flow before the quota is exhausted.
 *
 * Defined in 3GPP TS 29.244 §8.2.47. When the accumulated time of the
 * monitored traffic reaches this value the UPF shall report quota exhaustion
 * to the SMF via a Usage Report.
 */
struct time_quota {
  __u32 time_quota; /* seconds, big-endian */
} __attribute__((packed));

#endif /* _PFCP_IE_TIME_QUOTA_H */
