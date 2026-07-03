/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_REDIRECT_INFORMATION_H
#define _PFCP_REDIRECT_INFORMATION_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * enum pfcp_redirect_addr_type - Redirect address types
 * @PFCP_REDIRECT_ADDR_IPV4: IPv4 address
 * @PFCP_REDIRECT_ADDR_IPV6: IPv6 address
 * @PFCP_REDIRECT_ADDR_URL: URL
 * @PFCP_REDIRECT_ADDR_SIP_URI: SIP URI
 */
enum pfcp_redirect_addr_type {
  PFCP_REDIRECT_ADDR_IPV4    = 0,
  PFCP_REDIRECT_ADDR_IPV6    = 1,
  PFCP_REDIRECT_ADDR_URL     = 2,
  PFCP_REDIRECT_ADDR_SIP_URI = 3,
};

/**
 * struct redirect_information - Redirect Information IE
 * @base: Common IE header
 * @redirect_address_type: Type of redirect address (4 bits)
 * @spare: Spare bits
 * @redirect_server_address_length: Address length (network byte order)
 * @redirect_server_address: Variable length address
 *
 * Traffic redirection information.
 *
 * Flags layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |    spare      |    addr type  |
 * +---+---+---+---+---+---+---+---+
 */
struct redirect_information {
  // struct ie_base base;
  __u8 spare : 4, redirect_address_type : 4;
  __u16 redirect_server_address_length;
  __u8* redirect_server_address;
} __attribute__((packed));

#endif /* _PFCP_REDIRECT_INFORMATION_H */
