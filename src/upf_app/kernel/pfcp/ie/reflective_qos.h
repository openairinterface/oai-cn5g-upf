/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_REFLECTIVE_QOS_H
#define _PFCP_REFLECTIVE_QOS_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct rqi - Reflective QoS Indicator IE
 * @base: Common IE header
 * @rqi: Reflective QoS enabled (1 bit)
 * @spare: Spare bits
 *
 * When set, UE derives QoS flow parameters from downlink packets.
 *
 * Flags layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |           spare           |rqi|
 * +---+---+---+---+---+---+---+---+
 */
struct rqi {
  // struct ie_base base;
  __u8 spare : 7, rqi : 1;
} __attribute__((packed));

#endif /* _PFCP_REFLECTIVE_QOS_H */
