/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_PROXYING_H
#define _PFCP_PROXYING_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct proxying - Proxying IE
 * @base: Common IE header
 * @arp: ARP proxying enabled
 * @ins: IPv6 Neighbor Solicitation proxying enabled
 * @spare: Spare bits
 *
 * Indicates whether UPF should perform ARP/ND proxying for UE.
 *
 * Flags layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |    spare              |ins|arp|
 * +---+---+---+---+---+---+---+---+
 */
struct proxying {
  // struct ie_base base;
  __u8 spare : 6, ins : 1, arp : 1;
} __attribute__((packed));

#endif /* _PFCP_PROXYING_H */
