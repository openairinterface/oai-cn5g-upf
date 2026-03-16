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
 * PFCP Reporting Triggers
 * Reference: 3GPP TS 29.244 Section 8.2.41
 */

#ifndef _PFCP_REPORTING_TRIGGERS_H
#define _PFCP_REPORTING_TRIGGERS_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct reporting_triggers - Reporting Triggers IE
 * @volth: Volume Threshold reached
 * @volqu: Volume Quota exhausted
 * @timth: Time Threshold reached
 * @timqu: Time Quota exhausted
 * @perio: Periodic reporting
 * @start: Start of traffic detection
 * @stopt: Stop of traffic detection
 * @droth: Dropped DL traffic threshold
 *
 * Controls which events cause a Usage Report to be generated.
 */
struct reporting_triggers {
  // struct ie_base base;
  __u8 volth;
  __u8 volqu;
  __u8 timth;
  __u8 timqu;
  __u8 perio;
  __u8 start;
  __u8 stop;
  __u8 droth;
} __attribute__((packed));

#endif /* _PFCP_REPORTING_TRIGGERS_H */
