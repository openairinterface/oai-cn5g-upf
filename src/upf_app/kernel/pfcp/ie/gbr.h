/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP GBR (Guaranteed Bit Rate)
 * Reference: 3GPP TS 29.244 Section 8.2.9
 */

#ifndef _PFCP_GBR_H
#define _PFCP_GBR_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct gbr - Guaranteed Bit Rate IE
 * @base: Common IE header
 * @ul_gbr: Uplink GBR in kilobits per second (network byte order)
 * @dl_gbr: Downlink GBR in kilobits per second (network byte order)
 *
 * Specifies the guaranteed bit rate for uplink and downlink.
 * Values are in kbps (kilobits per second).
 */
struct gbr {
  // struct ie_base base;
  __u64 ul_gbr;
  __u64 dl_gbr;
} __attribute__((packed));

#endif /* _PFCP_GBR_H */
