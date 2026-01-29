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
 * PFCP Forwarding Policy
 * Reference: 3GPP TS 29.244 Section 8.2.23
 */

#ifndef _PFCP_FORWARDING_POLICY_H
#define _PFCP_FORWARDING_POLICY_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct forwarding_policy - Forwarding Policy IE
 * @base: Common IE header
 * @forwarding_policy_id_len: Length of policy identifier
 * @forwarding_policy_id: Forwarding policy identifier string
 *
 * Identifies a forwarding policy to be applied to matching traffic.
 */
struct forwarding_policy {
  // struct ie_base base;
  __u8 forwarding_policy_id_len;
  char forwarding_policy_id[PFCP_FORWARDING_POLICY_ID_MAX_LEN];
} __attribute__((packed));

#endif /* _PFCP_FORWARDING_POLICY_H */
