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
 * PFCP GBR (Guaranteed Bit Rate)
 * Reference: 3GPP TS 29.244 Section 8.2.9
 */

#ifndef _PFCP_GBR_H
#define _PFCP_GBR_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct gbr - Guaranteed Bit Rate IE
 * @base: Common IE header
 * @ul_gbr: Uplink GBR in kilobits per second (network byte order)
 * @dl_gbr: Downlink GBR in kilobits per second (network byte order)
 *
 * Specifies the guaranteed bit rate for uplink and downlink.
 * Values are in kbps (kilobits per second).
 */
struct gbr {
  // struct ie_base base;
  __u64 ul_gbr;
  __u64 dl_gbr;
} __attribute__((packed));

#endif /* _PFCP_GBR_H */
