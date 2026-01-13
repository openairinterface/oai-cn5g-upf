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
 * PFCP Application ID
 * Reference: 3GPP TS 29.244 Section 8.2.6
 */

#ifndef _PFCP_APPLICATION_ID_H
#define _PFCP_APPLICATION_ID_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct application_id - Application ID IE
 * @base: Common IE header
 * @application_id: Application identifier string
 *
 * Identifies an application for traffic detection and policy control.
 * Variable length string (e.g., "facebook", "youtube").
 */
struct application_id {
  struct ie_base base;
  char application_id[PFCP_APPLICATION_ID_MAX_LEN];
} __attribute__((packed));

#endif /* _PFCP_APPLICATION_ID_H */
