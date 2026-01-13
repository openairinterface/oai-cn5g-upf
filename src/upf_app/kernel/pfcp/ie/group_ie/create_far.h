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
 * PFCP Create FAR (Forwarding Action Rule)
 * Reference: 3GPP TS 29.244 Section 7.5.2.3
 * Table 7.5.2.3-1: Create FAR IE within PFCP Session Establishment Request
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
  struct ie_base base;
  struct far_id far_id;
  struct apply_action apply_action;
  struct forwarding_parameters forwarding_parameters;
  struct duplicating_parameters duplicating_parameters;
  struct bar_id bar_id;
} __attribute__((packed));

#endif /* _PFCP_CREATE_FAR_H */
