/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*
 * PFCP Activate Predefined Rules
 * Reference: 3GPP TS 29.244 Section 8.2.72
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
