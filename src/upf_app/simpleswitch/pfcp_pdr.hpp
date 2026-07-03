/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PFCP_PDR_HPP_SEEN
#define FILE_PFCP_PDR_HPP_SEEN

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <memory>
#include <mutex>
#include "endpoint.hpp"
#include "msg_pfcp.hpp"  // must precede FramedRouting.hpp (pfcp::framed_route_s)
#include "framed_routing/FramedRouting.hpp"

namespace pfcp {

class pfcp_session;

/** @brief Control-plane representation of a Packet Detection Rule (PDR).
 *
 *  Stores all IEs from 3GPP TS 29.244 V17.10.0 Table 7.5.2.2-1 (Create PDR)
 *  and Table 7.5.4.2-1 (Update PDR).  Used by pfcp_switch for per-packet
 *  look-up in both ACCESS (uplink) and CORE (downlink) directions.
 */
class pfcp_pdr {
 public:
  mutable std::mutex lock;

  // ---- Key -----------------------------------------------------------------
  uint64_t local_seid;  ///< UP session SEID this PDR belongs to

  // ---- Mandatory -----------------------------------------------------------
  pfcp::pdr_id_t pdr_id;  ///< §8.2.36 — Sxa+Sxb+Sxc+N4+N4mb

  // ---- Conditional / Optional ----------------------------------------------
  std::pair<bool, pfcp::precedence_t>
      precedence;                  ///< §8.2.11  — Sxb+Sxc+N4+N4mb
  std::pair<bool, pfcp::pdi> pdi;  ///< grouped IE type=2 — Sxa+Sxb+Sxc+N4+N4mb
  std::pair<bool, pfcp::outer_header_removal_t>
      outer_header_removal;                ///< §8.2.64  — Sxa+Sxb+N4+N4mb
  std::pair<bool, pfcp::far_id_t> far_id;  ///< §8.2.74  — Sxa+Sxb+Sxc+N4+N4mb
  std::pair<bool, pfcp::urr_id_t> urr_id;  ///< §8.2.54  — Sxa+Sxb+Sxc+N4
  std::pair<bool, pfcp::qer_id_t> qer_id;  ///< §8.2.75  — Sxb+Sxc+N4+N4mb
  std::pair<bool, pfcp::mar_id_t> mar_id;  ///< §8.2.123 — N4 only
  std::pair<bool, pfcp::activate_predefined_rules_t>
      activate_predefined_rules;  ///< §8.2.72  — Sxb+Sxc+N4

  // TODO §8.2.121 — Activation Time (O, Sxb+Sxc+N4,
  // Tables 7.5.2.2-1, 7.5.4.2-1)
  //   Not in lib (pfcp::create_pdr / pfcp::update_pdr).
  // TODO §8.2.122 — Deactivation Time (O, Sxb+Sxc+N4,
  // Tables 7.5.2.2-1, 7.5.4.2-1)
  //   Not in lib.
  // TODO §8.2.130 — Packet Replication and Detection Carry-On Information
  //   (C, N4 only, Table 7.5.2.2-1). Not in lib.
  // TODO §8.2.128 — UE IP address Pool Identity (O, Sxb+N4, Table 7.5.2.2-1).
  //   Not in lib.
  // TODO §8.2.181 — MPTCP Applicable Indication (C, N4 only, Table 7.5.2.2-1).
  //   Not in lib.
  // TODO           — IP Multicast Addressing Info (grouped IE type 188, O, N4,
  //   Table 7.5.2.2-4). Not in lib.
  // TODO           — Transport Delay Reporting (grouped IE type 271, C, N4,
  //   Tables 7.5.2.2-6, 7.5.4.2-1). Not in lib.
  // TODO §8.2.186 — RAT Type (O, N4 only, Table 7.5.4.2-1). Not in lib.

  bool notified_cp;  ///< true after a CP-Notify has been sent for this PDR

  //------------------------------------------------------------------------------
  /** @brief Construct with a UP SEID only (fields filled later via set()). */
  explicit pfcp_pdr(uint64_t lseid)
      : lock(),
        local_seid(lseid),
        pdr_id(),
        precedence(),
        pdi(),
        outer_header_removal(),
        far_id(),
        urr_id(),
        qer_id(),
        mar_id(),
        activate_predefined_rules(),
        notified_cp(false) {}

  //------------------------------------------------------------------------------
  /** @brief Construct from Create PDR IE (3GPP TS 29.244 V17.10.0
   *  Table 7.5.2.2-1).
   *  @note mar_id is left default-initialised: pfcp::create_pdr does not
   *  carry mar_id in the current OAI lib. Wire c.mar_id once lib is updated.
   */
  explicit pfcp_pdr(const pfcp::create_pdr& c)
      : lock(),
        local_seid(0),
        pdr_id(c.pdr_id.second),
        precedence(c.precedence),
        pdi(c.pdi),
        outer_header_removal(c.outer_header_removal),
        far_id(c.far_id),
        urr_id(c.urr_id),
        qer_id(c.qer_id),
        mar_id(),
        activate_predefined_rules(c.activate_predefined_rules),
        notified_cp(false) {}

  //------------------------------------------------------------------------------
  /** @brief Copy constructor. */
  pfcp_pdr(const pfcp_pdr& c)
      : lock(),
        precedence(c.precedence),
        pdi(c.pdi),
        outer_header_removal(c.outer_header_removal),
        far_id(c.far_id),
        urr_id(c.urr_id),
        qer_id(c.qer_id),
        mar_id(c.mar_id),
        activate_predefined_rules(c.activate_predefined_rules),
        notified_cp(c.notified_cp) {
    local_seid = c.local_seid;
    pdr_id     = c.pdr_id;
  }

  // ---- Setters -------------------------------------------------------------

  //------------------------------------------------------------------------------
  void set(const uint64_t& v) { local_seid = v; }

  //------------------------------------------------------------------------------
  void set(const pfcp::pdr_id_t& v) { pdr_id = v; }

  //------------------------------------------------------------------------------
  void set(const pfcp::precedence_t& v) {
    precedence.first  = true;
    precedence.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::pdi& v) {
    pdi.first  = true;
    pdi.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::outer_header_removal_t& v) {
    outer_header_removal.first  = true;
    outer_header_removal.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::far_id_t& v) {
    far_id.first  = true;
    far_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::urr_id_t& v) {
    urr_id.first  = true;
    urr_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::qer_id_t& v) {
    qer_id.first  = true;
    qer_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::mar_id_t& v) {
    mar_id.first  = true;
    mar_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::activate_predefined_rules_t& v) {
    activate_predefined_rules.first  = true;
    activate_predefined_rules.second = v;
  }

  // ---- Getters -------------------------------------------------------------

  //------------------------------------------------------------------------------
  bool get(uint64_t& v) const {
    v = local_seid;
    return true;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::pdr_id_t& v) const {
    v = pdr_id;
    return true;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::precedence_t& v) const {
    if (precedence.first) {
      v = precedence.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::pdi& v) const {
    if (pdi.first) {
      v = pdi.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::outer_header_removal_t& v) const {
    if (outer_header_removal.first) {
      v = outer_header_removal.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::far_id_t& v) const {
    if (far_id.first) {
      v = far_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::urr_id_t& v) const {
    if (urr_id.first) {
      v = urr_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::qer_id_t& v) const {
    if (qer_id.first) {
      v = qer_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::mar_id_t& v) const {
    if (mar_id.first) {
      v = mar_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::activate_predefined_rules_t& v) const {
    if (activate_predefined_rules.first) {
      v = activate_predefined_rules.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  /** @brief Apply Update PDR IE fields (3GPP TS 29.244 V17.10.0
   *  Table 7.5.4.2-1).
   *  @param updated_pdr Update PDR message IE.
   *  @param cause_value Populated with CAUSE_VALUE_* on return.
   *  @return true on success.
   */
  bool update(const pfcp::update_pdr& updated_pdr, uint8_t& cause_value);

  //------------------------------------------------------------------------------
  /** @brief Match an uplink packet against this PDR's PDI.
   *  @param iph        IPv4 header of the inner packet (GTP payload).
   *  @param num_bytes  Payload length in bytes.
   *  @param r_endpoint Remote endpoint (gNB address).
   *  @param tunnel_id  GTP-U TEID received on N3.
   *  @return true if the packet matches.
   */
  bool look_up_pack_in_access(
      struct iphdr* const iph, const std::size_t num_bytes,
      const endpoint& r_endpoint, const uint32_t tunnel_id);

  //------------------------------------------------------------------------------
  /** @brief Match a downlink packet against this PDR's PDI.
   *  @param iph        IPv4 header of the packet from the core network.
   *  @param num_bytes  Packet length in bytes.
   *  @return true if the packet matches.
   */
  bool look_up_pack_in_core(
      struct iphdr* const iph, const std::size_t num_bytes);

  //------------------------------------------------------------------------------
  /** @brief Buffer a downlink packet while waiting for paging to complete. */
  void buffering_requested(const char* buffer, const std::size_t num_bytes);

  //------------------------------------------------------------------------------
  /** @brief Send a Downlink Data Report to the CP function (3GPP TS 29.244
   *  V17.10.0 §8.2.21 — Report Type IE, DLDR flag). */
  void notify_cp_requested(std::shared_ptr<pfcp::pfcp_session> session);

  //------------------------------------------------------------------------------
  /** @brief Comparison by precedence — for sorted insertion in PDR vectors. */
  bool operator<(const pfcp_pdr& rhs) const {
    return (precedence.second.precedence < rhs.precedence.second.precedence);
  }
};
}  // namespace pfcp

#include "pfcp_session.hpp"

#endif  // FILE_PFCP_PDR_HPP_SEEN
