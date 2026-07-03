/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_CREATE_FAR_H
#define _PFCP_CREATE_FAR_H

#include "ie/ie_base.h"
#include "ie/far_id.h"
#include "ie/apply_action.h"
#include "forwarding_parameters.h"
#include "duplicating_parameters.h"
#include "ie/bar_id.h"

/**
 * struct create_far - Create Forwarding Action Rule IE
 * @base: Common IE header
 * @far_id: FAR identifier
 * @apply_action: Action flags (DROP/FORWARD/BUFFER/NOTIFY/DUPLICATE)
 * @forwarding_parameters: Forwarding instructions
 * @duplicating_parameters: Duplication instructions
 * @bar_id: Buffering Action Rule ID
 *
 * Provisions a Forwarding Action Rule defining packet actions.
 */
struct create_far {
  // struct ie_base base;
  struct far_id far_id;
  struct apply_action apply_action;
  struct forwarding_parameters forwarding_parameters;
  struct duplicating_parameters duplicating_parameters;
  struct bar_id bar_id;
} __attribute__((packed));

#endif /* _PFCP_CREATE_FAR_H */
