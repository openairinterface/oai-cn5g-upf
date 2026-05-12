/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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