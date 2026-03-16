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
 * PFCP Access Forwarding Action Information
 * Reference: 3GPP TS 29.244 Section 8.2.98
 */

#ifndef _PFCP_ACCESS_FORWARDING_ACTION_INFO_H
#define _PFCP_ACCESS_FORWARDING_ACTION_INFO_H

#include <linux/types.h>
#include "ie/far_id.h"

/**
 * struct access_forwarding_action_info - Access Forwarding Action Information
 * @far_id: FAR ID for this access type
 * @urr_id: URR ID for per-access usage reporting
 * @priority: Forwarding priority (0-255)
 * @weight: Load balancing weight (0-255)
 *
 * Per-access forwarding configuration within a MAR.
 * Info 1 = 3GPP access, Info 2 = non-3GPP access.
 */
struct access_forwarding_action_info {
  struct far_id far_id;
  __u32 urr_id;
  __u8 priority;
  __u8 weight;
  __u8 pad[2];
} __attribute__((packed));

#endif /* _PFCP_ACCESS_FORWARDING_ACTION_INFO_H */
