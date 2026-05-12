/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_IE_AVERAGING_WINDOW_H
#define _PFCP_IE_AVERAGING_WINDOW_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct averaging_window - Averaging Window IE
 * @averaging_window: Duration in milliseconds over which the GBR is
 *                    enforced for a GBR QoS flow (network byte order)
 *
 * Specifies the averaging window for QER enforcement per
 * 3GPP TS 29.244 §8.2.134, added in Release 17.10.0.
 */
struct averaging_window {
  __u32 averaging_window; /* milliseconds, big-endian */
} __attribute__((packed));

#endif /* _PFCP_IE_AVERAGING_WINDOW_H */
