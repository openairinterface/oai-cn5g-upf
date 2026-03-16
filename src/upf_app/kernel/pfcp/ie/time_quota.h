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
 * PFCP Time Quota IE
 * Reference: 3GPP TS 29.244 Section 8.2.47
 */
#ifndef _PFCP_IE_TIME_QUOTA_H
#define _PFCP_IE_TIME_QUOTA_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct time_quota - Time Quota IE
 * @time_quota: Maximum duration (in seconds, big-endian) allowed for a
 *              URR-monitored service data flow before the quota is exhausted.
 *
 * Defined in 3GPP TS 29.244 §8.2.47. When the accumulated time of the
 * monitored traffic reaches this value the UPF shall report quota exhaustion
 * to the SMF via a Usage Report.
 */
struct time_quota {
  __u32 time_quota; /* seconds, big-endian */
} __attribute__((packed));

#endif /* _PFCP_IE_TIME_QUOTA_H */
