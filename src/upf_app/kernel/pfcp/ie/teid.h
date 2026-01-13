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
 * PFCP Traffic Endpoint ID
 * Reference: 3GPP TS 29.244 Section 8.2.92
 */

#ifndef _PFCP_TEID_H
#define _PFCP_TEID_H

#include <linux/types.h>

/**
 * teid_t - Tunnel Endpoint Identifier
 *
 * 32-bit identifier used in GTP-U tunnels to multiplex connections.
 * Network byte order.
 */
typedef __u32 teid_t;
#define TEID_FMT "0x%" PRIx32
#define TEID_SCAN_FMT SCNx32
// #define INVALID_TEID             ((teid_t)0x00000000)
// #define UNASSIGNED_TEID          ((teid_t)0x00000000)

#endif  // IE_TEID_H
