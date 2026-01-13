/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP BAR ID (Buffering Action Rule ID)
 * Reference: 3GPP TS 29.244 Section 8.2.57
 */

#ifndef _PFCP_BAR_ID_H
#define _PFCP_BAR_ID_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct bar_id - Buffering Action Rule ID
 * @base: Common IE header
 * @bar_id: BAR identifier (8 bits)
 *
 * Uniquely identifies a Buffering Action Rule within a PFCP session.
 */
struct bar_id {
  // struct ie_base base;
  __u8 bar_id;
} __attribute__((packed));

#endif /* _PFCP_BAR_ID_H */
