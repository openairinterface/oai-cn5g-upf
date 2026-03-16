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
 * PFCP Averaging Window IE
 * Reference: 3GPP TS 29.244 Section 8.2.134 (V17.10.0)
 */
#ifndef _PFCP_IE_AVERAGING_WINDOW_H
#define _PFCP_IE_AVERAGING_WINDOW_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct averaging_window - Averaging Window IE
 * @averaging_window: Duration in milliseconds over which the GBR is
 *                    enforced for a GBR QoS flow (network byte order)
 *
 * Specifies the averaging window for QER enforcement per
 * 3GPP TS 29.244 §8.2.134, added in Release 17.10.0.
 */
struct averaging_window {
  __u32 averaging_window; /* milliseconds, big-endian */
} __attribute__((packed));

#endif /* _PFCP_IE_AVERAGING_WINDOW_H */
