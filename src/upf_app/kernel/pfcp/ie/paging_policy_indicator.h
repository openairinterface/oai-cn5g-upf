/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Paging Policy Indicator (PPI)
 * Reference: 3GPP TS 29.244 Section 8.2.116
 */
#ifndef _PFCP_PAGING_POLICY_INDICATOR_H
#define _PFCP_PAGING_POLICY_INDICATOR_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct paging_policy_indicator - Paging Policy Indicator IE
 * @base: Common IE header
 * @ppi_value: PPI value (0-7, 3 bits)
 * @spare: Spare bits
 *
 * Paging policy to apply. Values 0-7, higher value = higher priority.
 *
 * Flags layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |    spare          | PPI value |
 * +---+---+---+---+---+---+---+---+
 */
struct paging_policy_indicator {
  // struct ie_base base;
  __u8 spare : 5, ppi_value : 3;
} __attribute__((packed));

#endif /* _PFCP_PAGING_POLICY_INDICATOR_H */
