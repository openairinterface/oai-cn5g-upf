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
 * PFCP URR ID
 * Reference: 3GPP TS 29.244 Section 8.2.55
 */

#ifndef _PFCP_URR_ID_H
#define _PFCP_URR_ID_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct urr_id - Usage Reporting Rule ID
 * @base: Common IE header
 * @urr_id: URR identifier (network byte order)
 *
 * Uniquely identifies a Usage Reporting Rule within a PFCP session.
 * Used for charging and usage monitoring.
 */
struct urr_id {
  // struct ie_base base;
  __u32 urr_id;
} __attribute__((packed));

#endif /* _PFCP_URR_ID_H */
