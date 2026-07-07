/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_MEASUREMENT_METHOD_H
#define _PFCP_MEASUREMENT_METHOD_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct measurement_method - Measurement Method IE
 * @volum: Volume-based measurement
 * @durat: Duration-based measurement
 * @event: Event-based measurement
 * @pad: Alignment padding
 *
 * Indicates which measurement methods are active for a URR.
 */
struct measurement_method {
  // struct ie_base base;
  __u8 volum;
  __u8 durat;
  __u8 event;
  __u8 pad;
} __attribute__((packed));

#endif /* _PFCP_MEASUREMENT_METHOD_H */
