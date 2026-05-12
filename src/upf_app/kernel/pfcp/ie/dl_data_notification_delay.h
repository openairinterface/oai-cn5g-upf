/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_DL_DATA_NOTIFICATION_DELAY_H
#define _PFCP_DL_DATA_NOTIFICATION_DELAY_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct dl_data_notification_delay - DL Data Notification Delay IE
 * @delay_value: Delay in multiples of 50 milliseconds (0 = no delay)
 *
 * Specifies the delay before the UPF sends a DDN after buffering starts.
 */
struct dl_data_notification_delay {
  // struct ie_base base;
  __u8 delay_value;
} __attribute__((packed));

#endif /* _PFCP_DL_DATA_NOTIFICATION_DELAY_H */
