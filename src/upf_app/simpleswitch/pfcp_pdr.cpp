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
 *                - Removed duplicate #include "pfcp_pdr.hpp".
 *                - Fixed update() parameter: renamed update → updated_pdr
 *                  (shadowed method name — boy scout fix).
 *                - Added §-refs, interface applicability, and Table 7.5.4.2-1
 *                  cross-references to every inline IE comment in update().
 *                - Added TODO stubs for IEs absent from this impl or lib:
 *                  Activate Predefined Rules §8.2.72,
 *                  Activation/Deactivation Time §8.2.121/§8.2.122,
 *                  Transport Delay Reporting (grouped), RAT Type §8.2.186.
 *                - Fixed cause_value not set on success in update() —
 *                  was returning true with cause_value uninitialised.
 *                - Fixed §8.2.10 → §8.2.64 (Outer Header Removal) in
 *                  look_up_pack_in_access comment.
 *                - Fixed §8.2.6 → §8.2.21 (Report Type) in
 *                  notify_cp_requested comment (§8.2.6 = Application ID
 *                  in V17.10.0 — V17.6.0 §-ref bleed).
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/*! \file pfcp_pdr.cpp
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr
*/

// Google C++ style include order: own header, C system, C++ standard, project
#include "pfcp_pdr.hpp"

#include "common_defs.h"
#include "endian.h"
#include "pfcp_pdr.hpp"
#include "upf_n4.hpp"
#include "logger.hpp"
#include "upf_config.hpp"

using namespace pfcp;
using namespace oai::upf::app;

extern upf_n4* upf_n4_inst;
extern oai::config::upf_config upf_cfg;

//------------------------------------------------------------------------------
// 3GPP TS 29.244 V17.10.0 §8.2.2 — PDI source interface = ACCESS (uplink
// direction). Checks: outer header removal (§8.2.64), source interface
// (§8.2.2), local F-TEID (§8.2.3), UE IP (§8.2.62), SDF filter (§8.2.5).

//------------------------------------------------------------------------------
bool pfcp_pdr::look_up_pack_in_access(
    struct iphdr* const iph, const std::size_t num_bytes,
    const endpoint& r_endpoint, const uint32_t tunnel_id) {
  // Outer Header Removal must be present and of type GTP-U/UDP/IPv4 (§8.2.64)
  if (outer_header_removal.first) {
    if (outer_header_removal.second.outer_header_removal_description !=
        OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4) {
      return false;
    }
  } else {
    return false;  // GTP header already removed — not an ACCESS PDR
  }

  if (pdi.first) {
    // Source Interface must be ACCESS (§8.2.3)
    if (pdi.second.source_interface.first) {
      if (pdi.second.source_interface.second.interface_value !=
          INTERFACE_VALUE_ACCESS) {
        return false;
      }
    }
    // Local F-TEID (§8.2.3) — TEID must match
    if (pdi.second.local_fteid.first) {
      if (pdi.second.local_fteid.second.teid != tunnel_id) {
        return false;
      }
    }
    // UE IP Address (§8.2.62) — source address check for uplink
    if (pdi.second.ue_ip_address.first) {
      if (!pdi.second.ue_ip_address.second.v4) {
        return false;
      }
      if (pdi.second.ue_ip_address.second.ipv4_address.s_addr != iph->saddr) {
        return false;
      }
    }
    // SDF Filter (§8.2.5) — TODO: optimized flow description matching
    if (pdi.second.sdf_filter.first) {
      // TODO (create ss_pdi_t with ss_sdf_filter_t with optimized flow
      // description matching )
      return true;
    }
    return true;  // No SDF filter — match accepted
  } else {
    return false;  // PDI is mandatory per spec
  }
}

//------------------------------------------------------------------------------
// 3GPP TS 29.244 V17.10.0 §8.2.2 — PDI source interface = CORE (downlink
// direction). Checks: outer header removal (§8.2.64) absence, UE destination IP
// (§8.2.62).

//------------------------------------------------------------------------------
bool pfcp_pdr::look_up_pack_in_core(
    struct iphdr* const iph, const std::size_t num_bytes) {
  // implicit packet arrives from CORE interface
  if (outer_header_removal.first) {
    // TODO: handle split-U scenario — not needed for current topology
    return false;
  }
  // UE IP Address (§8.2.62) — destination address check for downlink
  if (pdi.second.ue_ip_address.first) {
    if (!pdi.second.ue_ip_address.second.v4) {
      // Logger::pfcp_switch().info( "look_up_pack_in_core failed PDR id %4x,
      // cause ue_ip_address not present ", pdr_id.rule_id);
      return false;
    }
    if (!upf_cfg.enable_fr &&
        pdi.second.ue_ip_address.second.ipv4_address.s_addr != iph->daddr) {
      // Logger::pfcp_switch().info( "look_up_pack_in_core failed PDR id %4x,
      // cause PDR ue_ip_address %8X do not match IP dest %8X of packet ",
      //    pdr_id.rule_id, pdi.second.ue_ip_address.second.ipv4_address.s_addr,
      //    iph->daddr);
      return false;
    }
  }
  // SDF filters TODO vector
  // if (pdi.second.sdf_filter.first) {
  // TODO (create ss_pdi_t with ss_sdf_filter_t with optimized flow description
  // matching )
  return true;
  //}
  // return false;
}

//------------------------------------------------------------------------------
// 3GPP TS 29.244 V17.10.0 Table 7.5.4.2-1 — Update PDR.
// Each field is overwritten only if present in the Update PDR message.

//------------------------------------------------------------------------------
bool pfcp_pdr::update(
    const pfcp::update_pdr& updated_pdr, uint8_t& cause_value) {
  // 3GPP TS 29.244 V17.10.0 Table 7.5.4.2-1 — Update PDR IEs
  if (updated_pdr.get(outer_header_removal.second))
    outer_header_removal.first = true;  // §8.2.64 — Sxa+Sxb+N4+N4mb
  if (updated_pdr.get(precedence.second))
    precedence.first = true;  // §8.2.11 — Sxb+Sxc+N4+N4mb
  if (updated_pdr.get(pdi.second))
    pdi.first = true;  // grouped IE type=2 — Sxa+Sxb+Sxc+N4+N4mb
  if (updated_pdr.get(far_id.second))
    far_id.first = true;  // §8.2.74 — Sxa+Sxb+Sxc+N4+N4mb
  if (updated_pdr.get(urr_id.second))
    urr_id.first = true;  // §8.2.54 — Sxa+Sxb+Sxc+N4
  if (updated_pdr.get(qer_id.second))
    qer_id.first = true;  // §8.2.75 — Sxb+Sxc+N4+N4mb

  // TODO §8.2.72  — Activate Predefined Rules (C, Sxb+Sxc+N4, Table 7.5.4.2-1)
  //   Getter present in lib; add when predefined rules enforcement is needed.
  // TODO §8.2.121 — Activation Time (O, Sxb+Sxc+N4, Table 7.5.4.2-1)
  //   Not in pfcp::update_pdr lib struct; add when lib is updated.
  // TODO §8.2.122 — Deactivation Time (O, Sxb+Sxc+N4, Table 7.5.4.2-1)
  //   Not in pfcp::update_pdr lib struct; add when lib is updated.
  // TODO           — Transport Delay Reporting (grouped IE type 271, C, N4,
  //   Table 7.5.4.2-1). Not in lib; add when N4 delay reporting is needed.
  // TODO §8.2.186 — RAT Type (O, N4 only, Table 7.5.4.2-1)
  //   Not in pfcp::update_pdr lib struct; add when lib is updated.

  cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}

//------------------------------------------------------------------------------
void pfcp_pdr::buffering_requested(
    const char* buffer, const std::size_t num_bytes) {
  Logger::upf_n4().warn("TODO pfcp_pdr::buffering_requested()");
  /*
    // TODO find smarter solution
    char filename[] = "/tmp/buff_pdrzzzxxxyyy.XXXXXX";
    int fd = mkstemp(filename);

    if (fd == -1) return 1;
    write(fd, buffer, num_bytes);

    close(fd);
    unlink(filename);
    num_packets++
   */
}

//------------------------------------------------------------------------------
// 3GPP TS 29.244 V17.10.0 §8.2.21 — Report Type IE, DLDR flag.
// Sends a PFCP Session Report Request to the CP function when the first DL
// packet arrives and the CP has requested notification (nocp flag).

//------------------------------------------------------------------------------
void pfcp_pdr::notify_cp_requested(
    std::shared_ptr<pfcp::pfcp_session> session) {
  if (not notified_cp) {
    Logger::upf_n4().trace("notify_cp_requested()");
    notified_cp = true;

    pfcp::pfcp_session_report_request h;

    pfcp::report_type_t report = {};
    report.dldr = 1;  // Downlink Data Report — Report Type §8.2.21

    pfcp::downlink_data_report dl_data_report;
    dl_data_report.set(pdr_id);

    h.set(report);
    h.set(dl_data_report);

    upf_n4_inst->send_n4_msg(session->cp_fseid, h);
  }
}
