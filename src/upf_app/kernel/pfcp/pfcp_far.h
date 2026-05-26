/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP FAR (Forwarding Action Rule)
 * Reference: 3GPP TS 29.244 Section 7.5.2.3
 */

#ifndef _PFCP_FAR_H
#define _PFCP_FAR_H

#include "ie/far_id.h"
#include "ie/apply_action.h"
#include "ie/group_ie/forwarding_parameters.h"
#include "ie/group_ie/duplicating_parameters.h"
#include "ie/bar_id.h"

/**
 * struct pfcp_far - Forwarding Action Rule
 * @far_id: FAR identifier
 * @apply_action: Action flags (DROP/FORWARD/BUFFER/NOTIFY/DUPLICATE)
 * @forwarding_parameters: Forwarding instructions
 * @duplicating_parameters: Duplication instructions
 * @bar_id: Buffering Action Rule ID
 *
 * FAR structure defining packet actions in PFCP sessions.
 */
struct pfcp_far {
  struct far_id far_id;
  struct apply_action apply_action;
  struct forwarding_parameters forwarding_parameters;
  struct duplicating_parameters duplicating_parameters;
  struct bar_id bar_id;
} __attribute__((packed));

typedef struct pfcp_far pfcp_far_t;

#endif /* _PFCP_FAR_H */
