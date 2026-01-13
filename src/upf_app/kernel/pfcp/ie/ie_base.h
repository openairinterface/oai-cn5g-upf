/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_IE_BASE_H
#define _PFCP_IE_BASE_H

#include <linux/types.h>

/**
 * struct ie_base - Base structure for all Information Elements
 * @type: IE type identifier (network byte order)
 * @length: Length of IE value in octets, excluding the 4-byte header (network
 * byte order)
 *
 * All PFCP IEs start with this 4-byte header structure.
 * Reference: 3GPP TS 29.244
 */
struct ie_base {
  __u16 type;
  __u16 length;
} __attribute__((packed));

#endif /* _PFCP_IE_BASE_H */
