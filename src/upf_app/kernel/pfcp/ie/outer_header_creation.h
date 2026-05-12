/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_OUTER_HEADER_CREATION_H
#define _PFCP_OUTER_HEADER_CREATION_H

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
 * enum pfcp_ohc_desc - Outer Header Creation description flags
 * @PFCP_OHC_GTP_U_UDP_IPV4: GTP-U/UDP/IPv4
 * @PFCP_OHC_GTP_U_UDP_IPV6: GTP-U/UDP/IPv6
 * @PFCP_OHC_UDP_IPV4: UDP/IPv4
 * @PFCP_OHC_UDP_IPV6: UDP/IPv6
 * @PFCP_OHC_IPV4: IPv4
 * @PFCP_OHC_IPV6: IPv6
 * @PFCP_OHC_C_TAG: C-TAG
 * @PFCP_OHC_S_TAG: S-TAG
 */
enum pfcp_ohc_desc {
  PFCP_OHC_GTP_U_UDP_IPV4 = 0x0100,
  PFCP_OHC_GTP_U_UDP_IPV6 = 0x0200,
  PFCP_OHC_UDP_IPV4       = 0x0400,
  PFCP_OHC_UDP_IPV6       = 0x0800,
  PFCP_OHC_IPV4           = 0x1000,
  PFCP_OHC_IPV6           = 0x2000,
  PFCP_OHC_C_TAG          = 0x4000,
  PFCP_OHC_S_TAG          = 0x8000,
};

/**
 * struct outer_header_creation - Outer Header Creation IE
 * @base: Common IE header
 * @description: Outer header creation description flags (network byte order)
 * @teid: TEID for GTP-U (when applicable)
 * @ipv4_address: IPv4 address
 * @ipv6_address: IPv6 address
 * @port_number: UDP port number (network byte order)
 * @ctag: C-TAG value (network byte order)
 * @stag: S-TAG value (network byte order)
 *
 * Specifies outer header(s) to create when forwarding packets.
 * Presence of fields depends on description flags.
 */
struct outer_header_creation {
  // struct ie_base base;
  __u16 description;
  teid_t teid;
  struct in_addr ipv4_address;
  struct in6_addr ipv6_address;
  __u16 port_number;
  __u16 ctag;
  __u16 stag;
} __attribute__((packed));

#endif  // __OUTER_HEADER_CREATION_H__
