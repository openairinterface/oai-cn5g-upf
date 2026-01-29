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
 * PFCP Framed-IPv6-Route
 * Reference: 3GPP TS 29.244 Section 8.2.111
 */

#ifndef _PFCP_FRAMED_IPV6_ROUTE_H
#define _PFCP_FRAMED_IPV6_ROUTE_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct framed_ipv6_route - Framed-IPv6-Route IE
 * @base: Common IE header
 * @framed_ipv6_route: IPv6 routing information (variable length)
 *
 * Contains IPv6 routing information for the UE.
 * Format as per RFC 3162 (RADIUS IPv6).
 */
struct framed_ipv6_route {
  // struct ie_base base;
  char framed_ipv6_route[PFCP_FRAMED_IPV6_ROUTE_MAX_LEN];
} __attribute__((packed));

#endif /* _PFCP_FRAMED_IPV6_ROUTE_H */
