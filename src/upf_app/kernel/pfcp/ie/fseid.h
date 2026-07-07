/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_FSEID_H
#define _PFCP_FSEID_H

#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
#include "ie_base.h"

/**
 * struct fseid - Fully Qualified Session Endpoint Identifier IE
 * @base: Common IE header
 * @v6: IPv6 address present
 * @v4: IPv4 address present
 * @spare: Spare bits
 * @seid: Session Endpoint Identifier (network byte order)
 * @ipv4_address: IPv4 address of CP function
 * @ipv6_address: IPv6 address of CP function
 *
 * Uniquely identifies a PFCP session endpoint with IP address.
 * SEID is unique per CP function node.
 *
 * Flags layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |    spare              | v4| v6|
 * +---+---+---+---+---+---+---+---+
 */
struct fseid {
  // struct ie_base base;
  __u8 spare : 6, v4 : 1, v6 : 1;
  __u64 seid;
  struct in_addr ipv4_address;
  struct in6_addr ipv6_address;
} __attribute__((packed));

#endif  // __FSEID_H__
