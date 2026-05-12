/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_ACTIVATE_PREDEFINED_RULES_H
#define _PFCP_ACTIVATE_PREDEFINED_RULES_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct activate_predefined_rules - Activate Predefined Rules IE
 * @base: Common IE header
 * @predefined_rules_name: Name of predefined rules to activate
 *
 * References a set of predefined rules to be activated.
 * Variable length string identifying the rule set.
 */
struct activate_predefined_rules {
  // struct ie_base base;
  char predefined_rules_name[PFCP_PREDEFINED_RULES_NAME_MAX_LEN];
} __attribute__((packed));

#endif /* _PFCP_ACTIVATE_PREDEFINED_RULES_H */
