/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PFCP_PDR_HPP_SEEN
#define FILE_PFCP_PDR_HPP_SEEN

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <atomic>
#include <memory>
#include <mutex>
#include "endpoint.hpp"
#include "msg_pfcp.hpp"  // must precede FramedRouting.hpp (pfcp::framed_route_s)
#include "framed_routing/FramedRouting.hpp"
#include "qos_mbr.hpp"
#include "sdf_filter.hpp"

namespace oai::upf {
class dl_packet_buffer;
}

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
  /// The mutex also makes pfcp_pdr non-assignable (std::mutex deletes copy
  /// and move assignment), so a rule is never overwritten in place and never
  /// keeps an old rule_uid. The user-declared copy constructor below
  /// suppresses the implicit move constructor, so a move is a copy too, and
  /// every copy takes a fresh rule_uid.
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

  /// MBR meter for this PDR's QoS flow, null when nothing limits it.
  /// Held here so the datapath finds it with the rule it already matched.
  ///
  /// Read and written only through std::atomic_load / std::atomic_store:
  /// pfcp_switch::apply_qos_mbr() replaces it on the N4 thread while the
  /// datapath threads are reading it per packet.
  std::shared_ptr<oai::upf::qos_mbr> qos;

  /// QFI for the PDU Session Container, resolved by
  /// pfcp_switch::resolve_pdr_qfis(); -1 when this PDR names none. A downlink
  /// PDR has no QFI in its PDI -- the linked QER carries it -- so it is
  /// resolved on the control plane rather than per packet.
  int16_t tx_qfi = -1;

  /// pdi.sdf_filter's Flow Description (§8.2.5), compiled once when the PDI
  /// is set: parsing it per packet would cost more than forwarding it.
  oai::upf::sdf_rule sdf;

  /// true after a CP-Notify has been sent for this PDR. Atomic because the
  /// DL threads set it (notify_cp_requested()) while TASK_UPF_APP clears it
  /// (rearm_notified_cp()).
  std::atomic<bool> notified_cp;

  /// Process-wide unique identity of this rule instance, used by the DL
  /// buffer (dl_packet_buffer.hpp) to tell the current BUFF rule from a
  /// removed or replaced one. Written once at construction and read-only
  /// after, so the datapath reads it without any atomic operation. Never
  /// reused and never copied: the copy made by an Update PDR (copy-on-write)
  /// gets a new value. Unlike the PDR's address, which a later allocation can
  /// reuse, it can never be mistaken for another rule.
  const uint64_t rule_uid;

  /// Next rule_uid. Starts at 1; 64 bits never wrap in practice.
  static uint64_t next_rule_uid() {
    static std::atomic<uint64_t> counter{1};
    return counter.fetch_add(1, std::memory_order_relaxed);
  }

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
        notified_cp(false),
        rule_uid(next_rule_uid()) {}

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
        notified_cp(false),
        rule_uid(next_rule_uid()) {
    compile_sdf();
  }

  //------------------------------------------------------------------------------
  /** @brief Copy constructor. Takes a fresh rule_uid, never c.rule_uid. */
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
        qos(c.qos),
        tx_qfi(c.tx_qfi),
        sdf(c.sdf),
        notified_cp(c.notified_cp.load()),
        rule_uid(next_rule_uid()) {
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
    compile_sdf();
  }

  //------------------------------------------------------------------------------
  /** @brief UE IPv4 from the PDI, network byte order; 0 when absent.
   *  This is what an IPFilterRule's "assigned" resolves to. */
  uint32_t pdi_ue_ipv4() const {
    return (pdi.first && pdi.second.ue_ip_address.first &&
            pdi.second.ue_ip_address.second.v4) ?
               pdi.second.ue_ip_address.second.ipv4_address.s_addr :
               0;
  }

  //------------------------------------------------------------------------------
  /** @brief Recompile the SDF rule. Every path that writes pdi must call it,
   *  or the filter and the rule it is meant to enforce drift apart. */
  void compile_sdf() {
    sdf = (pdi.first && pdi.second.sdf_filter.first) ?
              oai::upf::sdf_compile(
                  pdi.second.sdf_filter.second.flow_description) :
              oai::upf::sdf_rule();
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
  /** @brief Hold a copy of a downlink packet while the UE is paged.
   *
   *  DL threads. Hands the packet to `store`, which decides whether to keep
   *  it. Never throws.
   *  @return true when the packet is now held. */
  bool buffering_requested(
      oai::upf::dl_packet_buffer& store, const char* buffer,
      const std::size_t num_bytes);

  //------------------------------------------------------------------------------
  /** @brief Send a Downlink Data Report to the CP function (3GPP TS 29.244
   *  V17.10.0 §8.2.21 — Report Type IE, DLDR flag), once per episode.
   *
   *  DL threads. The first caller claims notified_cp. If the report cannot be
   *  queued, the latch stays held and the next DL buffer tick releases it,
   *  so there is at most one attempt per tick. */
  void notify_cp_requested(
      oai::upf::dl_packet_buffer& store,
      std::shared_ptr<pfcp::pfcp_session> session);

  //------------------------------------------------------------------------------
  /** @brief Comparison by precedence — for sorted insertion in PDR vectors. */
  bool operator<(const pfcp_pdr& rhs) const {
    return (precedence.second.precedence < rhs.precedence.second.precedence);
  }
};

//------------------------------------------------------------------------------
/**
 * @brief Re-arm the one-shot CP notification latch of every PDR of a FAR.
 *
 * Called when a FAR leaves buffering, so that the next idle period reports
 * again. Simple-switch counterpart of BARProgram::ResetBarState(). Other
 * re-arms go through pfcp_switch::rearm_dl_notification().
 *
 * @param pdrs    The session's PDRs (null entries are ignored).
 * @param far_id  FAR that left buffering; only PDRs using it are re-armed.
 * @return Number of PDRs whose latch was actually cleared.
 */
inline size_t rearm_notified_cp(
    const std::vector<std::shared_ptr<pfcp_pdr>>& pdrs, uint32_t far_id) {
  size_t rearmed = 0;
  for (const auto& pdr : pdrs) {
    if (!pdr) continue;
    if (!pdr->far_id.first) continue; /* PDR references no FAR */
    if (pdr->far_id.second.far_id != far_id) continue;
    if (!pdr->notified_cp.load()) continue; /* nothing latched */
    pdr->notified_cp.store(false);
    ++rearmed;
  }
  return rearmed;
}
}  // namespace pfcp

#include "pfcp_session.hpp"

#endif  // FILE_PFCP_PDR_HPP_SEEN
