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
 * PFCP SDF Filter
 * Reference: 3GPP TS 29.244 Section 8.2.5
 */

#ifndef _PFCP_SDF_FILTER_H
#define _PFCP_SDF_FILTER_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * struct sdf_filter - Service Data Flow Filter IE
 * @base: Common IE header
 * @fd: Flow Description present
 * @ttc: ToS Traffic Class present
 * @spi: Security Parameter Index present
 * @fl: Flow Label present
 * @bid: Bidirectional filter
 * @spare: Spare bits
 * @flow_desc_len: Length of flow description (network byte order)
 * @flow_description: IPFilterRule format (e.g., "permit out tcp from any to
 * assigned 80")
 * @tos_traffic_class: Type of Service / Traffic Class (2 octets)
 * @security_param_index: IPsec SPI (4 octets)
 * @flow_label: IPv6 Flow Label (3 octets)
 * @sdf_filter_id: SDF Filter ID (network byte order)
 *
 * Packet filter for service data flow detection.
 *
 * Flags layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |    spare  |bid|fl |spi|ttc|fd |
 * +---+---+---+---+---+---+---+---+
 */
struct sdf_filter {
  struct ie_base base;
  __u8 spare : 3, bid : 1, fl : 1, spi : 1, ttc : 1, fd : 1;
  __u16 flow_desc_len;
  char flow_description[PFCP_SDF_FLOW_DESC_MAX_LEN];
  __u8 tos_traffic_class[2];
  __u8 security_param_index[4];
  __u8 flow_label[3];
  __u32 sdf_filter_id;
} __attribute__((packed));

#endif /* _PFCP_SDF_FILTER_H */
