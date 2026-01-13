/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP QFI
 * Reference: 3GPP TS 29.244 Section 8.2.89
 */
#ifndef _PFCP_QFI_H
#define _PFCP_QFI_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct qfi - QoS Flow Identifier
 * @base: Common IE header
 * @qfi: QoS Flow Identifier value (6 bits, 0-63)
 * @spare: Spare bits (2 bits)
 *
 * Identifies QoS flows within a PDU session in 5G networks.
 *
 * Octet layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |spare  |    QFI (6 bits)       |
 * +---+---+---+---+---+---+---+---+
 */
struct qfi {
  // struct ie_base base;
  __u8 qfi : 6;
  __u8 spare : 2;
} __attribute__((packed));

#endif /* _PFCP_QFI_H */
