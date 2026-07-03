/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_MBR_H
#define _PFCP_MBR_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct mbr - Maximum Bit Rate IE
 * @base: Common IE header
 * @ul_mbr: Uplink MBR in kilobits per second (network byte order)
 * @dl_mbr: Downlink MBR in kilobits per second (network byte order)
 *
 * Specifies the maximum bit rate for uplink and downlink.
 * Values are in kbps (kilobits per second).
 */
struct mbr {
  // struct ie_base base;
  __u64 ul_mbr;
  __u64 dl_mbr;
} __attribute__((packed));

#endif /* _PFCP_MBR_H */
