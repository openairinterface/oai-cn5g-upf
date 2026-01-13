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
 * PFCP Transport Level Marking
 * Reference: 3GPP TS 29.244 Section 8.2.12
 */

#ifndef _PFCP_TRANSPORT_LEVEL_MARKING_H
#define _PFCP_TRANSPORT_LEVEL_MARKING_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct transport_level_marking - Transport Level Marking IE
 * @base: Common IE header
 * @tos_traffic_class: ToS/Traffic Class value and mask (2 octets)
 *
 * ToS (IPv4) or Traffic Class (IPv6) value for QoS marking.
 * Octet 0: value, Octet 1: mask
 */
struct transport_level_marking {
  struct ie_base base;
  __u8 tos_traffic_class[2];
} __attribute__((packed));

#endif /* _PFCP_TRANSPORT_LEVEL_MARKING_H */
