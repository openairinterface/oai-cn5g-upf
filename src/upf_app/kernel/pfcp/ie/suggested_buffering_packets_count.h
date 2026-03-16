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
 * PFCP Suggested Buffering Packets Count
 * Reference: 3GPP TS 29.244 Section 8.2.100
 */

#ifndef _PFCP_SUGGESTED_BUFFERING_PACKETS_COUNT_H
#define _PFCP_SUGGESTED_BUFFERING_PACKETS_COUNT_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct suggested_buffering_packets_count - Suggested Buffering Packets Count IE
 * @packet_count: Suggested max DL packets to buffer (0 = no limit hint)
 *
 * SMF hint for how many downlink packets the UPF should buffer per UE.
 */
struct suggested_buffering_packets_count {
  // struct ie_base base;
  __u8 packet_count;
} __attribute__((packed));

#endif /* _PFCP_SUGGESTED_BUFFERING_PACKETS_COUNT_H */
