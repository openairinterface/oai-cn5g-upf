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
 * PFCP Packet Detection Information (PDI)
 * Reference: 3GPP TS 29.244 Section 7.5.2.2
 * Table 7.5.2.2-2: PDI IE within PFCP Session Establishment Request
 */

#ifndef _PFCP_PDI_H
#define _PFCP_PDI_H

#include "ie/ie_base.h"
#include "ie/source_interface.h"
#include "ie/fteid.h"
#include "ie/network_instance.h"
#include "ie/ue_ip_address.h"
#include "ie/traffic_endpoint_id.h"
#include "ie/sdf_filter.h"
#include "ie/application_id.h"
#include "ie/ethernet_pdu_session_information.h"
#include "ie/qfi.h"
#include "ie/framed_route.h"
#include "ie/framed_routing.h"
#include "ie/framed_ipv6_route.h"

/**
 * struct pdi - Packet Detection Information IE
 * @base: Common IE header
 * @source_interface: Source interface type
 * @fteid: F-TEID for packet detection
 * @network_instance: Network instance identifier
 * @ue_ip_address: UE IP address for matching
 * @traffic_endpoint_id: Traffic endpoint identifier
 * @sdf_filter: Service Data Flow filter
 * @application_id: Application identifier
 * @ethernet_pdu_session_information: Ethernet PDU session info
 * @qfi: QoS Flow Identifier
 * @framed_route: IPv4 framed route
 * @framed_routing: Framed routing method
 * @framed_ipv6_route: IPv6 framed route
 *
 * Contains packet detection information for identifying packets
 * belonging to a specific PDR (Packet Detection Rule).
 */
struct pdi {
  struct ie_base base;
  struct source_interface source_interface;
  struct fteid fteid;
  struct network_instance network_instance;
  struct ue_ip_address ue_ip_address;
  struct traffic_endpoint_id traffic_endpoint_id;
  struct sdf_filter sdf_filter;
  struct application_id application_id;
  struct ethernet_pdu_session_information ethernet_pdu_session_information;
  struct qfi qfi;
  struct framed_route framed_route;
  struct framed_routing framed_routing;
  struct framed_ipv6_route framed_ipv6_route;
} __attribute__((packed));

#endif /* _PFCP_PDI_H */
