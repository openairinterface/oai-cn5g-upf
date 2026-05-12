/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_PDR_ID_H
#define _PFCP_PDR_ID_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct pdr_id - Packet Detection Rule ID
 * @base: Common IE header
 * @rule_id: PDR identifier (network byte order, valid range 1-65535)
 *
 * Uniquely identifies a Packet Detection Rule within a PFCP session.
 */
struct pdr_id {
  // struct ie_base base;
  __u16 rule_id;
} __attribute__((packed));

#endif /* _PFCP_PDR_ID_H */
