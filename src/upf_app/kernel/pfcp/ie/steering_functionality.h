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
 * PFCP Steering Functionality
 * Reference: 3GPP TS 29.244 Section 8.2.96
 */

#ifndef _PFCP_STEERING_FUNCTIONALITY_H
#define _PFCP_STEERING_FUNCTIONALITY_H

#include <linux/types.h>
#include "ie_base.h"

#define STEERING_FUNC_ATSSS_LL  0  /* ATSSS Low Layer */
#define STEERING_FUNC_MPTCP     1  /* MPTCP           */

/**
 * struct steering_functionality - Steering Functionality IE
 * @steering_functionality_value: STEERING_FUNC_* enum
 *
 * Indicates ATSSS-LL or MPTCP steering functionality.
 */
struct steering_functionality {
  // struct ie_base base;
  __u8 steering_functionality_value;
} __attribute__((packed));

#endif /* _PFCP_STEERING_FUNCTIONALITY_H */
