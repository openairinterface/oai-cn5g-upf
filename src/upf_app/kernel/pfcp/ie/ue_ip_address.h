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
 * PFCP UE IP Address
 * Reference: 3GPP TS 29.244 Section 8.2.62
 */

#ifndef _PFCP_UE_IP_ADDRESS_H
#define _PFCP_UE_IP_ADDRESS_H

#include <linux/types.h>
#ifdef KERNEL_SPACE
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif
#include <linux/in6.h>
#include "ie_base.h"

/**
 * struct ue_ip_address - UE IP Address IE
 * @base: Common IE header
 * @v6: IPv6 address present
 * @v4: IPv4 address present
 * @sd: Source (0) or Destination (1) address
 * @ipv6d: IPv6 prefix delegation present
 * @spare: Spare bits
 * @ipv4_address: IPv4 address
 * @ipv6_address: IPv6 address
 * @ipv6_prefix_delegation_bits: IPv6 prefix length (default 64)
 *
 * UE IP address for PDU session. Both IPv4 and IPv6 can be present
 * (dual-stack). In PDI: SD bit indicates source (0) or destination (1)
 * matching.
 *
 * Flags layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+-----+-----+-----+-----+
 * |      spare    |ipv6d| sd  |  v4  | v6 |
 * +---+---+---+---+-----+-----+-----+-----+
 */
struct ue_ip_address {
  // struct ie_base base;
  __u8 spare : 4, ipv6d : 1, sd : 1, v4 : 1, v6 : 1;
  struct in_addr ipv4_address;
  struct in6_addr ipv6_address;
  __u8 ipv6_prefix_delegation_bits;
} __attribute__((packed));

#endif /* _PFCP_UE_IP_ADDRESS_H */
