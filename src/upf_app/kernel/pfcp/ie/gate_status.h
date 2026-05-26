/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Gate Status
 * Reference: 3GPP TS 29.244 Section 8.2.7
 */

#ifndef _PFCP_GATE_STATUS_H
#define _PFCP_GATE_STATUS_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * enum pfcp_gate_status_value - Gate status values
 * @PFCP_GATE_OPEN: Gate is open (traffic allowed)
 * @PFCP_GATE_CLOSED: Gate is closed (traffic blocked)
 */
enum pfcp_gate_status_value {
  PFCP_GATE_OPEN   = 0,
  PFCP_GATE_CLOSED = 1,
};

/**
 * struct gate_status - Gate Status IE
 * @base: Common IE header
 * @ul_gate: Uplink gate status (2 bits)
 * @dl_gate: Downlink gate status (2 bits)
 * @spare: Spare bits (4 bits)
 *
 * Controls traffic gating in uplink and downlink directions.
 *
 * Bit layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |    spare      |ul_gate|dl_gate|
 * +---+---+---+---+---+---+---+---+
 */
struct gate_status {
  // struct ie_base base;
  __u8 spare : 4, ul_gate : 2, dl_gate : 2;
} __attribute__((packed));

#endif /* _PFCP_GATE_STATUS_H */
