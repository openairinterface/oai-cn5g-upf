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

// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Boy Scout cleanup — Doxygen, 3GPP §-refs, separator lines,
 *              Google C++ include order.
 *              V17.10.0 harmonisation:
 *                - Version bump V17.6.0 → V17.10.0.
 *                - Fixed §8.2.17 → §8.2.26 (Apply Action) in section header
 *                  and inline comment.
 *                - Fixed §8.2.15 → grouped IE type=4 (Forwarding Parameters)
 *                  in inline comment.
 *                - Fixed update() parameter: renamed update → updated_far
 *                  (shadowed method name — boy scout fix).
 *                - Added §-refs, interface applicability, and Table 7.5.4.3-1
 *                  cross-references to every IE line in update().
 *                - Added TODO stubs for IEs absent from lib: Redundant
 *                  Transmission Forwarding Parameters (grouped=270), Add MBS
 *                  Unicast Parameters (grouped=302), Remove MBS Unicast
 *                  Parameters (grouped=303).
 *                - Fixed cause_value not set on success in update() —
 *                  was returning true with cause_value uninitialised.
 *                - Fixed build error: added reinterpret_cast<struct ::iphdr*>
 *                  at no_internal_loop() / send_to_core() call sites.
 *                  pfcp_far.cpp does `using namespace pfcp` so unqualified
 *                  `iphdr` resolves to pfcp::iphdr; pfcp_switch expects the
 *                  Linux kernel ::iphdr.  Both types are layout-identical.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/*! \file pfcp_far.cpp
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr
*/

#include "pfcp_far.hpp"

#include "logger.hpp"
#include "simple_switch.hpp"
#include "upf_config.hpp"
#include "pfcp_switch.hpp"

// using namespace pfcp;
using namespace oai::upf::app;
using namespace oai::config;

extern pfcp_switch* pfcp_switch_inst;
extern upf_n3* upf_n3_inst;
extern upf_config upf_cfg;

namespace pfcp {
//------------------------------------------------------------------------------
// apply_forwarding_rules — execute the FAR action on a matched packet.
// Apply Action flags (3GPP TS 29.244 V17.10.0 §8.2.26):
//   forw — Forward packet per Forwarding Parameters (grouped IE type=4)
//   drop — Silently discard the packet
//   buff — Buffer packet; caller sets buff=true and handles buffering
//   nocp — Notify CP; caller sets nocp=true and triggers CP report
//   dupl — Duplicate (TODO — not yet implemented)

//------------------------------------------------------------------------------
void pfcp_far::apply_forwarding_rules(
    struct iphdr* const iph, const std::size_t num_bytes, bool& nocp,
    bool& buff, uint8_t qfi) {
  // TODO dupl
  // TODO nocp
  // TODO buff
  // Logger::pfcp_switch().info( "pfcp_far::apply_forwarding_rules FAR id %4x ",
  // far_id.far_id);
  if (apply_action.forw) {
    if (forwarding_parameters.first) {
      auto rule = forwarding_parameters.second;
      if (rule.destination_interface.first) {
        if (rule.destination_interface.second.interface_value ==
            INTERFACE_VALUE_ACCESS) {
          if (rule.outer_header_creation.first) {
            switch (rule.outer_header_creation.second
                        .outer_header_creation_description) {
              case OUTER_HEADER_CREATION_GTPU_UDP_IPV4:
                upf_n3_inst->send_g_pdu(
                    rule.outer_header_creation.second.ipv4_address,
                    upf_cfg.n3.port, rule.outer_header_creation.second.teid,
                    reinterpret_cast<const char*>(iph), num_bytes, qfi);

                break;
              case OUTER_HEADER_CREATION_GTPU_UDP_IPV6:
                upf_n3_inst->send_g_pdu(
                    rule.outer_header_creation.second.ipv6_address,
                    upf_cfg.n3.port, rule.outer_header_creation.second.teid,
                    reinterpret_cast<const char*>(iph), num_bytes);
                break;
              case OUTER_HEADER_CREATION_UDP_IPV4:  // TODO
              case OUTER_HEADER_CREATION_UDP_IPV6:  // TODO
              default:;
            }
          }
        } else if (
            rule.destination_interface.second.interface_value ==
                INTERFACE_VALUE_CORE ||
            rule.destination_interface.second.interface_value ==
                INTERFACE_VALUE_CP_FUNCTION) {
          if (!upf_cfg.enable_bpf_datapath) {
            // Cast required: `using namespace pfcp` makes unqualified `iphdr`
            // resolve to pfcp::iphdr here, but no_internal_loop / send_to_core
            // expect the Linux kernel ::iphdr.  The two types are
            // layout-identical so reinterpret_cast is safe.
            if (pfcp_switch_inst->no_internal_loop(
                    reinterpret_cast<struct ::iphdr*>(iph), num_bytes)) {
              pfcp_switch_inst->send_to_core(
                  reinterpret_cast<char* const>(iph), num_bytes);
            }
          }
        } else {
        }
      } else {
        // Destination Interface is mandatory when apply_action.forw is set
      }
    } else {
      // Forwarding Parameters mandatory when forw flag is set (grouped IE
      // type=4)
    }
  } else if (apply_action.drop) {
    // Drop — nothing to do, packet is silently discarded
  } else if (apply_action.buff) {
    buff = true;
  }

  if (apply_action.nocp) {
    nocp = true;
  }
}

//------------------------------------------------------------------------------
// update() — 3GPP TS 29.244 V17.10.0 Table 7.5.4.3-1 (Update FAR).
// Patches apply_action and forwarding/duplicating parameters in-place.
// PFCPSMReq-Flags (§8.2.31) is tracked but not yet fully handled.

//------------------------------------------------------------------------------
bool pfcp_far::update(
    const pfcp::update_far& updated_far, uint8_t& cause_value) {
  // 3GPP TS 29.244 V17.10.0 Table 7.5.4.3-1 — Update FAR IEs
  set(updated_far.apply_action.second);  // §8.2.26 — Sxa+Sxb+Sxc+N4+N4mb (C)

  if (updated_far.update_forwarding_parameters.first) {
    // Update Forwarding Parameters — grouped IE type=11, Table 7.5.4.3-2
    // Sxa+Sxb+Sxc+N4
    forwarding_parameters.first = true;
    forwarding_parameters.second.update(
        updated_far.update_forwarding_parameters.second);

    if (updated_far.update_forwarding_parameters.second.pfcpsmreq_flags.first) {
      // TODO §8.2.31 — PFCPSMReq-Flags (Table 7.5.4.3-2, Sxa+Sxb+Sxc+N4):
      //   DROBU: Drop Buffered Packets — trigger dropping of buffered DL pkts.
      //   SNDEM: Send End Marker — trigger GTP-U End Marker towards gNB.
      //   QAURR: Query URR — trigger immediate usage report for assoc. URRs.
      //   Currently not handled; add when SNDEM/DROBU signalling is needed.
    }
  }

  if (updated_far.update_duplicating_parameters.first) {
    // Update Duplicating Parameters — grouped IE type=105, Table 7.5.4.3-3
    // Sxa+Sxb only
    duplicating_parameters.first = true;
    duplicating_parameters.second.update(
        updated_far.update_duplicating_parameters.second);
  }

  if (updated_far.get(bar_id.second))
    bar_id.first = true;  // §8.2.57 — Sxa+N4 (C)

  // TODO grouped=270 — Redundant Transmission Forwarding Parameters
  //   (C, N4 only, Table 7.5.4.3-1). Not in lib; add when N4 redundant
  //   transmission is needed.
  // TODO grouped=302 — Add MBS Unicast Parameters
  //   (C, N4mb only, Table 7.5.4.3-1). Not in lib.
  // TODO grouped=303 — Remove MBS Unicast Parameters
  //   (C, N4mb only, Table 7.5.4.3-1). Not in lib.

  cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}
}  // namespace pfcp