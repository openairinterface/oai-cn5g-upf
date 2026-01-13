/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Precedence
 * Reference: 3GPP TS 29.244 Section 8.2.11
 */
#ifndef _PFCP_PRECEDENCE_H
#define _PFCP_PRECEDENCE_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct precedence - Precedence IE
 * @base: Common IE header
 * @precedence: Precedence value (network byte order)
 *
 * Evaluation precedence among multiple PDRs.
 * Lower value = higher precedence (evaluated first).
 */
struct precedence {
  // struct ie_base base;
  __u32 precedence;
} __attribute__((packed));

#endif /* _PFCP_PRECEDENCE_H */
