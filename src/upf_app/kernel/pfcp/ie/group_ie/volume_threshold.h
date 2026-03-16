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
 * PFCP Volume Threshold
 * Reference: 3GPP TS 29.244 Section 8.2.34
 */

#ifndef _PFCP_VOLUME_THRESHOLD_H
#define _PFCP_VOLUME_THRESHOLD_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct volume_threshold - Volume Threshold IE
 * @total_volume: Total volume threshold (bytes)
 * @uplink_volume: Uplink volume threshold (bytes)
 * @downlink_volume: Downlink volume threshold (bytes)
 *
 * Volume-based reporting threshold for Usage Reporting Rules.
 */
struct volume_threshold {
  // struct ie_base base;
  __u64 total_volume;
  __u64 uplink_volume;
  __u64 downlink_volume;
} __attribute__((packed));

#endif /* _PFCP_VOLUME_THRESHOLD_H */
