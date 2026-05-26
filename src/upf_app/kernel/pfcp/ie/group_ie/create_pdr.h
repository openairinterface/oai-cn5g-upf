/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Create PDR (Packet Detection Rule)
 * Reference: 3GPP TS 29.244 Section 7.5.2.2
 * Table 7.5.2.2-1: Create PDR IE within PFCP Session Establishment Request
 */

#ifndef _PFCP_CREATE_PDR_H
#define _PFCP_CREATE_PDR_H

#include "ie/ie_base.h"
#include "ie/pdr_id.h"
#include "ie/precedence.h"
#include "pdi.h"
#include "ie/outer_header_removal.h"
#include "ie/far_id.h"
#include "ie/urr_id.h"
#include "ie/qer_id.h"
#include "ie/activate_predefined_rules.h"

/**
 * struct create_pdr - Create Packet Detection Rule IE
 * @base: Common IE header
 * @pdr_id: PDR identifier
 * @precedence: Rule precedence for matching order
 * @pdi: Packet Detection Information
 * @outer_header_removal: Outer header removal instructions
 * @far_id: Associated FAR ID
 * @urr_id: Associated URR ID(s)
 * @qer_id: Associated QER ID(s)
 * @activate_predefined_rules: Predefined rules activation
 *
 * Provisions a Packet Detection Rule for packet classification.
 */
struct create_pdr {
  // struct ie_base base;
  struct pdr_id pdr_id;
  struct precedence precedence;
  struct pdi pdi;
  struct outer_header_removal outer_header_removal;
  struct far_id far_id;
  struct urr_id urr_id;
  struct qer_id qer_id;
  struct activate_predefined_rules activate_predefined_rules;
} __attribute__((packed));

#endif /* _PFCP_CREATE_PDR_H */
