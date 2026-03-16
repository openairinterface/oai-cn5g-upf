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
 * PFCP Downlink Data Notification Delay
 * Reference: 3GPP TS 29.244 Section 8.2.28
 */

#ifndef _PFCP_DL_DATA_NOTIFICATION_DELAY_H
#define _PFCP_DL_DATA_NOTIFICATION_DELAY_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct dl_data_notification_delay - DL Data Notification Delay IE
 * @delay_value: Delay in multiples of 50 milliseconds (0 = no delay)
 *
 * Specifies the delay before the UPF sends a DDN after buffering starts.
 */
struct dl_data_notification_delay {
  // struct ie_base base;
  __u8 delay_value;
} __attribute__((packed));

#endif /* _PFCP_DL_DATA_NOTIFICATION_DELAY_H */
