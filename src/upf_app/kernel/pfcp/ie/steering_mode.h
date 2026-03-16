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
 * PFCP Steering Mode
 * Reference: 3GPP TS 29.244 Section 8.2.97
 */

#ifndef _PFCP_STEERING_MODE_H
#define _PFCP_STEERING_MODE_H

#include <linux/types.h>
#include "ie_base.h"

#define STEER_MODE_ACTIVE_STANDBY  0  /* Active-Standby */
#define STEER_MODE_SMALLEST_DELAY  1  /* Smallest Delay */
#define STEER_MODE_LOAD_BALANCE    2  /* Load Balancing */
#define STEER_MODE_PRIORITY_BASED  3  /* Priority-Based */

/**
 * struct steering_mode - Steering Mode IE
 * @steer_mode_value: STEER_MODE_* enum
 *
 * Indicates the ATSSS steering mode for multi-access traffic.
 */
struct steering_mode {
  // struct ie_base base;
  __u8 steer_mode_value;
} __attribute__((packed));

#endif /* _PFCP_STEERING_MODE_H */
