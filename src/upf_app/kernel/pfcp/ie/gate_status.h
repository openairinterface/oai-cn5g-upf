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
 * PFCP Gate Status
 * Reference: 3GPP TS 29.244 Section 8.2.7
 */

#ifndef _PFCP_GATE_STATUS_H
#define _PFCP_GATE_STATUS_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * enum pfcp_gate_status_value - Gate status values
 * @PFCP_GATE_OPEN: Gate is open (traffic allowed)
 * @PFCP_GATE_CLOSED: Gate is closed (traffic blocked)
 */
enum pfcp_gate_status_value {
  PFCP_GATE_OPEN   = 0,
  PFCP_GATE_CLOSED = 1,
};

/**
 * struct gate_status - Gate Status IE
 * @base: Common IE header
 * @ul_gate: Uplink gate status (2 bits)
 * @dl_gate: Downlink gate status (2 bits)
 * @spare: Spare bits (4 bits)
 *
 * Controls traffic gating in uplink and downlink directions.
 *
 * Bit layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |    spare      |ul_gate|dl_gate|
 * +---+---+---+---+---+---+---+---+
 */
struct gate_status {
  // struct ie_base base;
  __u8 spare : 4, ul_gate : 2, dl_gate : 2;
} __attribute__((packed));

#endif /* _PFCP_GATE_STATUS_H */
