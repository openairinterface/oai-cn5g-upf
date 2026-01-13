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
 * PFCP Ethernet PDU Session Information
 * Reference: 3GPP TS 29.244 Section 8.2.102
 */

#ifndef _PFCP_ETHERNET_PDU_SESSION_INFORMATION_H
#define _PFCP_ETHERNET_PDU_SESSION_INFORMATION_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct ethernet_pdu_session_information - Ethernet PDU Session Info IE
 * @base: Common IE header
 * @ethi: Ethernet indication flag
 * @spare: Spare bits
 *
 * Indicates if the PDU session is for Ethernet PDUs.
 *
 * Bit layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |          spare           |ethi|
 * +---+---+---+---+---+---+---+---+
 */
struct ethernet_pdu_session_information {
  // struct ie_base base;
  __u8 spare : 7, ethi : 1;
} __attribute__((packed));
;

#endif /* _PFCP_ETHERNET_PDU_SESSION_INFORMATION_H */
