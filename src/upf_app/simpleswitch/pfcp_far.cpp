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

/*! \file pfcp_far.cpp
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr
*/

#include "pfcp_far.hpp"
#include "pfcp_switch.hpp"
#include "upf_config.hpp"
#include "simple_switch.hpp"
#include "upf_n6.hpp"

using namespace pfcp;
using namespace oai::upf::app;
using namespace oai::config;

extern pfcp_switch* pfcp_switch_inst;
extern upf_n3* upf_n3_inst;
extern upf_n6* upf_n6_inst; // [TS-SFC] add upf_n6_inst
extern upf_config upf_cfg;

//------------------------------------------------------------------------------
void pfcp_far::apply_forwarding_rules(
    struct iphdr* const iph, const std::size_t num_bytes, bool& nocp,
    bool& buff, uint8_t qfi) {
  // TODO dupl
  // TODO nocp
  // TODO buff
  // Logger::pfcp_switch().debug( "pfcp_far::apply_forwarding_rules FAR id %4x ",
  // far_id.far_id);
  if (apply_action.forw) {
    if (forwarding_parameters.first) {
      if (forwarding_parameters.second.destination_interface.first) {
        if (forwarding_parameters.second.destination_interface.second
                .interface_value == INTERFACE_VALUE_ACCESS) {
          if (forwarding_parameters.second.outer_header_creation.first) {
            switch (forwarding_parameters.second.outer_header_creation.second
                        .outer_header_creation_description) {
              case OUTER_HEADER_CREATION_GTPU_UDP_IPV4:
                upf_n3_inst->send_g_pdu(
                    forwarding_parameters.second.outer_header_creation.second
                        .ipv4_address,
                    upf_cfg.n3.port,
                    forwarding_parameters.second.outer_header_creation.second
                        .teid,
                    reinterpret_cast<const char*>(iph), num_bytes, qfi);

                break;
              case OUTER_HEADER_CREATION_GTPU_UDP_IPV6:
                upf_n3_inst->send_g_pdu(
                    forwarding_parameters.second.outer_header_creation.second
                        .ipv6_address,
                    upf_cfg.n3.port,
                    forwarding_parameters.second.outer_header_creation.second
                        .teid,
                    reinterpret_cast<const char*>(iph), num_bytes);
                break;
              case OUTER_HEADER_CREATION_UDP_IPV4:  // TODO
              case OUTER_HEADER_CREATION_UDP_IPV6:  // TODO
              default:;
            }
          }
        } else if (
            forwarding_parameters.second.destination_interface.second
                .interface_value == INTERFACE_VALUE_CORE) {
          if (!upf_cfg.enable_bpf_datapath) {
            if (pfcp_switch_inst->no_internal_loop(iph, num_bytes)) {
              pfcp_switch_inst->send_to_core(
                  reinterpret_cast<char* const>(iph), num_bytes);
            }
          }
        } else if (
            forwarding_parameters.second.destination_interface.second
                .interface_value == INTERFACE_VALUE_SGI_LAN_N6_LAN) {
          if (forwarding_parameters.second.outer_header_creation.first) {
            switch (forwarding_parameters.second.outer_header_creation.second
                        .outer_header_creation_description) {
              case OUTER_HEADER_CREATION_NSH: // TODO [SFC] check name in standards
              // TODO [TS-SFC] add NSH header creation
              // Send to n6 interface
              case OUTER_HEADER_CREATION_UDP_IPV4:  // TODO
              case OUTER_HEADER_CREATION_UDP_IPV6:  // TODO
              default:;
            }
          } else if (forwarding_parameters.second.forwarding_policy.first) { 
            // TODO [TS-SFC] reference the pre-configured Forwarding Policy in the UP function TS 29 244 8.2.23 Forwarding Policy
            /* The Forwarding Policy Identifier shall be set to the Traffic Steering Policy Identifier [TS  29.244 5.4.8 Traffic Steering]
             * Based on the received traffic steering policy identifier(s), the UPF may remove or insert VLAN tags on N6 interface for downlink 
             * and uplink frames, respectively. The details of the scenario are defined in clause 5.6.10.2 of TS 23.501 */
            
            /* [TR 23.700-18 7] Suggests that the TSP ID can be reused to steer traffic e.g., as the SFC ID */
            /*
              This should also include the traffic steering information and metadata.
              How do will pass the data? Is this part of the buff? or do we need to create
              add new parameters. The traffic steering information includes the TSP ID
              corresponding to the SFC ID (in some cases this is a direct map) and the 
              metadata of the rule, which can be included in the NSH metadata.
            */
            // Question: The TSP ID refers to a pre-configure forwarding policy, how and where is the policy pre-configured
            // Question: What is the schema of the pre-configured policy
            Logger::pfcp_switch().info("Received forwarding policy request %s", forwarding_parameters.second.forwarding_policy.second
                        .forwarding_policy_identifier);
            // TODO [TS-SFC] get metadata from the supplied info
            // For now sending without metadata
            
            // TODO [TS-SFC] implement logic for fetching the pre-configured forwarding policy.
            // For now default to sending NSH with 0 for SPI and SI
            
            upf_n6_inst->send_nsh(reinterpret_cast<char*>(iph), num_bytes,  0x112233, 0x03);

            // int metadata_len = 16; // The length MUST be an integer multiple of 4 always padded out to a multiple of 4 bytes.
            // char metadata[metadata_len]; 
            // memset(metadata, 0, metadata_len);

            // upf_n6_inst->send_nsh(
            //   reinterpret_cast<char*>(iph), num_bytes,
            //   0x112233, 0x03, metadata, metadata_len
            // );
          } else {
            // TODO [TS-SFC] support multiple N6 interface and selection of interface
            upf_n6_inst->send_to_n6(reinterpret_cast<char*>(iph), num_bytes);
          }
        } else {
        }
      } else {
        // Mandatory IE
      }
    } else {
      // Mandatory if FW set in apply action
    }
  } else if (apply_action.drop) {
    // DONE !
  } else if (apply_action.buff) {
    buff = true;
  }

  if (apply_action.nocp) {
    nocp = true;
  }
}

//------------------------------------------------------------------------------
bool pfcp_far::update(const pfcp::update_far& update, uint8_t& cause_value) {
  set(update.apply_action.second);
  if (update.update_forwarding_parameters.first) {
    forwarding_parameters.first = true;
    forwarding_parameters.second.update(
        update.update_forwarding_parameters.second);
    if (update.update_forwarding_parameters.second.pfcpsmreq_flags.first) {
      // TODO
    }
  }
  if (update.update_duplicating_parameters.first) {
    duplicating_parameters.second.update(
        update.update_duplicating_parameters.second);
  }
  if (update.get(bar_id.second)) bar_id.first = true;
  return true;
}
