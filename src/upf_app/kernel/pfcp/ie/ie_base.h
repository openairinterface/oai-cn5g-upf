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

#ifndef _PFCP_IE_BASE_H
#define _PFCP_IE_BASE_H

#include <linux/types.h>

/**
 * struct ie_base - Base structure for all Information Elements
 * @type: IE type identifier (network byte order)
 * @length: Length of IE value in octets, excluding the 4-byte header (network
 * byte order)
 *
 * All PFCP IEs start with this 4-byte header structure.
 * Reference: 3GPP TS 29.244
 */
struct ie_base {
  __u16 type;
  __u16 length;
} __attribute__((packed));

#endif /* _PFCP_IE_BASE_H */
