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
 * PFCP Forwarding Parameters
 * Reference: 3GPP TS 29.244 Section 7.5.2.3
 * Table 7.5.2.3-2: Forwarding Parameters IE in FAR
 */

#ifndef _PFCP_FORWARDING_PARAMETERS_H
#define _PFCP_FORWARDING_PARAMETERS_H

#include "ie/ie_base.h"
#include "ie/destination_interface.h"
#include "ie/redirect_information.h"
#include "ie/outer_header_creation.h"
#include "ie/transport_level_marking.h"
#include "ie/forwarding_policy.h"
#include "ie/header_enrichment.h"
#include "ie/traffic_endpoint_id.h"
#include "ie/proxying.h"

/**
 * struct forwarding_parameters - Forwarding Parameters IE
 * @base: Common IE header
 * @destination_interface: Destination interface type
 * @redirect_information: HTTP redirect information
 * @outer_header_creation: Outer header encapsulation
 * @transport_level_marking: DSCP/ToS marking
 * @forwarding_policy: Forwarding policy identifier
 * @header_enrichment: Header enrichment instructions
 * @traffic_endpoint_id: Traffic endpoint identifier
 * @proxying: Proxying instructions
 *
 * Contains forwarding instructions when FORWARD action is applied in FAR.
 */
struct forwarding_parameters {
  // struct ie_base base;
  struct destination_interface destination_interface;
  struct redirect_information redirect_information;
  struct outer_header_creation outer_header_creation;
  struct transport_level_marking transport_level_marking;
  struct forwarding_policy forwarding_policy;
  struct header_enrichment header_enrichment;
  struct traffic_endpoint_id traffic_endpoint_id;
  struct proxying proxying;
} __attribute__((packed));

#endif /* _PFCP_FORWARDING_PARAMETERS_H */
