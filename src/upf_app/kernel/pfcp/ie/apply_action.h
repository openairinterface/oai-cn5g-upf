/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_APPLY_ACTION_H
#define _PFCP_APPLY_ACTION_H
#include <linux/types.h>
#include "ie_base.h"

/**
 * struct apply_action - Apply Action IE
 * @base: Common IE header
 * @drop: DROP action (bit 0 / bit 1 in 1-indexed)
 * @forw: FORWARD action (bit 1 / bit 2 in 1-indexed)
 * @buff: BUFFER action (bit 2 / bit 3 in 1-indexed)
 * @nocp: NOTIFY CP action (bit 3 / bit 4 in 1-indexed)
 * @dupl: DUPLICATE action (bit 4 / bit 5 in 1-indexed)
 * @spare: Spare bits (bits 5-7 / bits 6-8 in 1-indexed)
 *
 * Indicates the action(s) to apply to packets matching a PDR.
 * Multiple actions can be combined.
 *
 * Bit layout (3GPP TS 29.244 uses 1-indexed bit numbering):
 *   8    7    6    5    4    3    2    1
 * +----+----+----+----+----+----+----+----+
 * |spare         |dupl|nocp|buff|forw|drop|
 * +----+----+----+----+----+----+----+----+
 */
struct apply_action {
  // struct ie_base base;
  __u8 drop : 1, forw : 1, buff : 1, nocp : 1, dupl : 1, spare : 3;
} __attribute__((packed));

/* Apply Action bit masks (3GPP TS 29.244 Section 8.2.26) */
#define PFCP_APPLY_ACTION_DROP 0x01 /* Bit 1 (3GPP 1-indexed): 0b00000001 */
#define PFCP_APPLY_ACTION_FORW 0x02 /* Bit 2 (3GPP 1-indexed): 0b00000010 */
#define PFCP_APPLY_ACTION_BUFF 0x04 /* Bit 3 (3GPP 1-indexed): 0b00000100 */
#define PFCP_APPLY_ACTION_NOCP 0x08 /* Bit 4 (3GPP 1-indexed): 0b00001000 */
#define PFCP_APPLY_ACTION_DUPL 0x10 /* Bit 5 (3GPP 1-indexed): 0b00010000 */

#endif /* _PFCP_APPLY_ACTION_H */

/**************************************************** */

// /*
//  * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
//  * contributor license agreements.  See the NOTICE file distributed with
//  * this work for additional information regarding copyright ownership.
//  * The OpenAirInterface Software Alliance licenses this file to You under
//  * the OAI Public License, Version 1.1  (the "License"); you may not use this
//  * file except in compliance with the License. You may obtain a copy of the
//  * License at
//  *
//  *      http://www.openairinterface.org/?page_id=698
//  *
//  * Unless required by applicable law or agreed to in writing, software
//  * distributed under the License is distributed on an "AS IS" BASIS,
//  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  * See the License for the specific language governing permissions and
//  * limitations under the License.
//  *-------------------------------------------------------------------------------
//  * For more information about the OpenAirInterface (OAI) Software Alliance:
//  *      contact@openairinterface.org
//  */

// /*
//  * PFCP Apply Action
//  * Reference: 3GPP TS 29.244 Section 8.2.26
//  */

// #ifndef _PFCP_APPLY_ACTION_H
// #define _PFCP_APPLY_ACTION_H

// #include <linux/types.h>
// #include "ie_base.h"

// /**
//  * struct apply_action - Apply Action IE
//  * @base: Common IE header
//  * @drop: DROP action (bit 0)
//  * @forw: FORWARD action (bit 1)
//  * @buff: BUFFER action (bit 2)
//  * @nocp: NOTIFY CP action (bit 3)
//  * @dupl: DUPLICATE action (bit 4)
//  * @spare: Spare bits (bits 5-7)
//  *
//  * Indicates the action(s) to apply to packets matching a PDR.
//  * Multiple actions can be combined.
//  *
//  * Bit layout:
//  *   7    6    5    4    3    2    1    0
//  * +----+----+----+----+----+----+----+----+
//  * |spare         |dupl|nocp|buff|forw|drop|
//  * +----+----+----+----+----+----+----+----+
//  */
// struct apply_action {
//   struct ie_base base;
//   __u8 spare : 3, dupl : 1, nocp : 1, buff : 1, forw : 1, drop : 1;
// } __attribute__((packed));

// /* Apply Action bit masks */
// #define PFCP_APPLY_ACTION_DUPL 0x08 /* Bit 3: 0b00001000 */
// #define PFCP_APPLY_ACTION_NOCP 0x10 /* Bit 4: 0b00010000 */
// #define PFCP_APPLY_ACTION_BUFF 0x20 /* Bit 5: 0b00100000 */
// #define PFCP_APPLY_ACTION_FORW 0x40 /* Bit 6: 0b01000000 */
// #define PFCP_APPLY_ACTION_DROP 0x80 /* Bit 7: 0b10000000 */

// #endif /* _PFCP_APPLY_ACTION_H */
