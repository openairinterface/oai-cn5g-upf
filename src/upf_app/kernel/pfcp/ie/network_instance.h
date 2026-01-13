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
 * PFCP Network Instance
 * Reference: 3GPP TS 29.244 Section 8.2.4
 */

#ifndef _PFCP_NETWORK_INSTANCE_H
#define _PFCP_NETWORK_INSTANCE_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct network_instance - Network Instance IE
 * @base: Common IE header
 * @network_instance: Network instance name (APN/DNN format)
 *
 * Identifies the PDN/Data Network (e.g., "internet", "ims").
 */
struct network_instance {
  struct ie_base base;
  char network_instance[PFCP_NETWORK_INSTANCE_MAX_LEN];
} __attribute__((packed));
;

#endif /* _PFCP_NETWORK_INSTANCE_H */
