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
 * PFCP QFI
 * Reference: 3GPP TS 29.244 Section 8.2.89
 */
#ifndef _PFCP_QFI_H
#define _PFCP_QFI_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct qfi - QoS Flow Identifier
 * @base: Common IE header
 * @qfi: QoS Flow Identifier value (6 bits, 0-63)
 * @spare: Spare bits (2 bits)
 *
 * Identifies QoS flows within a PDU session in 5G networks.
 *
 * Octet layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |spare  |    QFI (6 bits)       |
 * +---+---+---+---+---+---+---+---+
 */
struct qfi {
  // struct ie_base base;
  __u8 qfi : 6;
  __u8 spare : 2;
} __attribute__((packed));

#endif /* _PFCP_QFI_H */
