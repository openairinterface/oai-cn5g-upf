/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP F-TEID (Fully Qualified TEID)
 * Reference: 3GPP TS 29.244 Section 8.2.3
 */

#ifndef _PFCP_FTEID_H
#define _PFCP_FTEID_H

#include <linux/types.h>
#ifdef KERNEL_SPACE
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif
#include <linux/in6.h>
#include "ie_base.h"
#include "teid.h"

/**
 * struct fteid - Fully Qualified TEID IE
 * @base: Common IE header
 * @v4: IPv4 address present
 * @v6: IPv6 address present
 * @ch: CHOOSE flag (CP selects TEID/IP)
 * @chid: CHOOSE ID present
 * @spare: Spare bits
 * @teid: Tunnel Endpoint Identifier
 * @ipv4_address: IPv4 address
 * @ipv6_address: IPv6 address
 * @choose_id: CHOOSE ID value (when chid=1)
 *
 * Identifies a GTP-U tunnel endpoint with IP address.
 * If CH=1, the CP function requests UP function to assign TEID/IP.
 *
 * Flags layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |      spare    |chid|ch| v6| v4|
 * +---+---+---+---+---+---+---+---+
 */
struct fteid {
  // struct ie_base base;
  __u8 spare : 4, chid : 1, ch : 1, v6 : 1, v4 : 1;
  teid_t teid;
  struct in_addr ipv4_address;
  struct in6_addr ipv6_address;
  __u8 choose_id;
} __attribute__((packed));

#endif /* _PFCP_FTEID_H */
