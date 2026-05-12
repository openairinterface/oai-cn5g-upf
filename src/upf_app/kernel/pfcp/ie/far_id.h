/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_FAR_ID_H
#define _PFCP_FAR_ID_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct far_id - Forwarding Action Rule ID
 * @base: Common IE header
 * @far_id: FAR identifier (network byte order)
 *
 * Uniquely identifies a Forwarding Action Rule within a PFCP session.
 */
struct far_id {
  // struct ie_base base;
  __u32 far_id;
} __attribute__((packed));

#endif /* _PFCP_FAR_ID_H */
