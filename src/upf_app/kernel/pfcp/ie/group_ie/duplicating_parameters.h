/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Duplicating Parameters
 * Reference: 3GPP TS 29.244 Section 7.5.2.3
 * Table 7.5.2.3-3: Duplicating Parameters IE in FAR
 */

#ifndef _PFCP_DUPLICATING_PARAMETERS_H
#define _PFCP_DUPLICATING_PARAMETERS_H

#include "ie/ie_base.h"
#include "ie/destination_interface.h"
#include "ie/outer_header_creation.h"
#include "ie/transport_level_marking.h"
#include "ie/forwarding_policy.h"

/**
 * struct duplicating_parameters - Duplicating Parameters IE
 * @base: Common IE header
 * @destination_interface: Destination interface for duplicated packets
 * @outer_header_creation: Outer header encapsulation for copy
 * @transport_level_marking: DSCP/ToS marking for copy
 * @forwarding_policy: Forwarding policy for duplicated packets
 *
 * Contains duplication instructions when DUPLICATE action is applied in FAR.
 */
struct duplicating_parameters {
  // struct ie_base base;
  struct destination_interface destination_interface;
  struct outer_header_creation outer_header_creation;
  struct transport_level_marking transport_level_marking;
  struct forwarding_policy forwarding_policy;
} __attribute__((packed));

#endif /* _PFCP_DUPLICATING_PARAMETERS_H */
