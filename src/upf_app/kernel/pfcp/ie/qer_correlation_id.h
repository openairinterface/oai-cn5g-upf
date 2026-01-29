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
 * PFCP QER Correlation ID
 * Reference: 3GPP TS 29.244 Section 8.2.10
 */

#ifndef _PFCP_QER_CORRELATION_ID_H
#define _PFCP_QER_CORRELATION_ID_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct qer_correlation_id - QER Correlation ID IE
 * @base: Common IE header
 * @qer_correlation_id: Correlation ID (network byte order)
 *
 * Correlates QERs across different PFCP sessions or nodes.
 */
struct qer_correlation_id {
  // struct ie_base base;
  __u32 qer_correlation_id;
} __attribute__((packed));

#endif /* _PFCP_QER_CORRELATION_ID_H */
