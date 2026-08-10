/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PFCP_SESSION_HPP_SEEN
#define FILE_PFCP_SESSION_HPP_SEEN

#include "3gpp_29.244.h"
#include "msg_pfcp.hpp"  // must precede FramedRouting.hpp (pfcp::framed_route_s)
#include "framed_routing/FramedRouting.hpp"
#include "pfcp_bar.hpp"
#include "pfcp_far.hpp"
#include "pfcp_mar.hpp"
#include "pfcp_pdr.hpp"
#include "pfcp_qer.hpp"
#include "pfcp_urr.hpp"

namespace pfcp {

#define PFCP

/** @brief Per-PDU-session container for all active PFCP rules.
 *
 *  Holds vectors of PDR / FAR / QER / URR / BAR / MAR shared pointers and
 *  provides typed create / update / remove methods that mirror the 3GPP
 *  TS 29.244 Session-Establishment (§7.5.2) and Session-Modification (§7.5.4)
 *  IE groups.
 */
class pfcp_session {
 private:
  // ---- Internal add helpers (upsert semantics) ----------------------------
  void add(std::shared_ptr<pfcp::pfcp_far>);  ///< Upsert FAR into fars vector
  void add(std::shared_ptr<pfcp::pfcp_pdr>);  ///< Upsert PDR into pdrs vector
  void add(std::shared_ptr<pfcp::pfcp_qer>);  ///< Upsert QER into qers vector
  void add(std::shared_ptr<pfcp::pfcp_urr>);  ///< Upsert URR into urrs vector
  void add(std::shared_ptr<pfcp::pfcp_bar>);  ///< Upsert BAR into bars vector
  void add(std::shared_ptr<pfcp::pfcp_mar>);  ///< Upsert MAR into mars vector

  //------------------------------------------------------------------------------
  bool remove(const pfcp::far_id_t& far_id, uint8_t& cause_value);
  bool remove(const pfcp::pdr_id_t& pdr_id, uint8_t& cause_value);
  bool remove(const pfcp::qer_id_t& qer_id, uint8_t& cause_value);

  //------------------------------------------------------------------------------
  std::mutex teid_mutex;  ///< Guards teid_uplink read/write
  /** @brief Store the allocated uplink F-TEID (thread-safe via teid_mutex). */
  void set(const pfcp::fteid_t& fteid);

  //------------------------------------------------------------------------------
  std::mutex pdn_type_mutex;  ///< Guards pdn_type read/write
  /** @brief Set the PDN type for this session (§8.2.79, thread-safe). */
  void set(pfcp::pdn_type_value_e type);

 public:
  // ---- Session identifiers -------------------------------------------------
  pfcp::fseid_t cp_fseid;  ///< CP F-SEID (3GPP TS 29.244 §8.2.37)
  uint64_t seid;           ///< UP SEID allocated locally

  // ---- PDN context ---------------------------------------------------------
  pfcp::pdn_type_value_e pdn_type;  ///< PDN type (IPv4/IPv6/IPv4v6/Ethernet),
                                    ///< default is 0 (undefined)
  uint8_t qfi = 0x05;  ///< Default QFI for DN-originated packets (§8.2.89)

  // TO DO better than this :(sooner the better)  when inserting or removing new
  // PDRs, FARS, should not conflict with switching operations

  // ---- Rule vectors (3GPP TS 29.244 §7.5.2) --------------------------------
  // TO DO: add locking for concurrent insert/remove vs. switching operations.
  std::vector<std::shared_ptr<pfcp::pfcp_pdr>>
      pdrs;  ///< Packet Detection Rules §7.5.2.2
  std::vector<std::shared_ptr<pfcp::pfcp_far>>
      fars;  ///< Forwarding Action Rules §7.5.2.3
  std::vector<std::shared_ptr<pfcp::pfcp_qer>>
      qers;  ///< QoS Enforcement Rules §7.5.2.5
  std::vector<std::shared_ptr<pfcp::pfcp_urr>>
      urrs;  ///< Usage Reporting Rules §7.5.2.4
  std::vector<std::shared_ptr<pfcp::pfcp_bar>>
      bars;  ///< Buffering Action Rules §7.5.2.6
  std::vector<std::shared_ptr<pfcp::pfcp_mar>>
      mars;  ///< Multi-Access Rules §7.5.2.8

  // ---- Direction-split PDR caches (populated by pfcp_switch) ---------------
  std::vector<std::shared_ptr<pfcp::pfcp_pdr>>
      pdrs_uplink;  ///< ACCESS-interface PDRs
  std::vector<std::shared_ptr<pfcp::pfcp_pdr>>
      pdrs_downlink;  ///< CORE-interface PDRs

  // ---- Direction-split QER caches ------------------------------------------
  std::vector<std::shared_ptr<pfcp::pfcp_qer>> qers_uplink;  ///< Uplink QERs
  std::vector<std::shared_ptr<pfcp::pfcp_qer>>
      qers_downlink;  ///< Downlink QERs

  pfcp::fteid_t teid_uplink = {};  ///< Allocated N3 F-TEID (§8.2.3)

  //------------------------------------------------------------------------------
  /** @brief Default constructor — reserves typical rule vector capacities. */
  pfcp_session()
      : cp_fseid(), seid(0), pdrs(), fars(), qers(), urrs(), bars(), mars() {
    pdrs.reserve(8);
    fars.reserve(8);
    qers.reserve(8);
    urrs.reserve(4);
    bars.reserve(4);
    mars.reserve(2);
  }

  //------------------------------------------------------------------------------
  /** @brief Construct with CP F-SEID and UP SEID. */
  pfcp_session(pfcp::fseid_t& cp, uint64_t up_seid) : pfcp_session() {
    cp_fseid = cp;
    seid     = up_seid;
  }

  //------------------------------------------------------------------------------
  /** @brief Copy constructor (deep-copies all rule vectors). */
  pfcp_session(const pfcp_session& c)
      : cp_fseid(c.cp_fseid),
        seid(c.seid),
        pdrs(c.pdrs),
        fars(c.fars),
        qers(c.qers),
        urrs(c.urrs),
        bars(c.bars),
        mars(c.mars),
        teid_uplink(c.teid_uplink),
        pdn_type(c.pdn_type) {}

  //------------------------------------------------------------------------------
  virtual ~pfcp_session() {
    cleanup();
    cp_fseid = {};
    seid     = {};
  };

  //------------------------------------------------------------------------------
  /** @brief Remove all rules and release tun/teid mappings via pfcp_switch. */
  void cleanup();

  //------------------------------------------------------------------------------
  /** @brief Render session rules as a formatted ASCII table string. */
  std::string to_string() const;

  //------------------------------------------------------------------------------
  /** @brief Return the UP SEID allocated for this session. */
  uint64_t get_up_seid() const { return seid; };

  // ---- Lookup by ID --------------------------------------------------------

  //------------------------------------------------------------------------------
  /** @brief Find a FAR by its 32-bit FAR ID (§8.2.74). */
  bool get(const uint32_t, std::shared_ptr<pfcp::pfcp_far>&) const;

  /** @brief Find a PDR by its 16-bit PDR ID (§8.2.36). */
  bool get(const uint16_t, std::shared_ptr<pfcp::pfcp_pdr>&) const;

  /** @brief Find a QER by its 32-bit QER ID (§8.2.75). */
  bool get(const uint32_t, std::shared_ptr<pfcp::pfcp_qer>&) const;

  /** @brief Find a URR by its 32-bit URR ID (§8.2.54). */
  bool get(const uint32_t, std::shared_ptr<pfcp::pfcp_urr>&) const;

  /** @brief Find a BAR by its 8-bit BAR ID (§8.2.57). */
  bool get(const uint8_t, std::shared_ptr<pfcp::pfcp_bar>&) const;

  /** @brief Find a MAR by its 8-bit MAR ID (§8.2.123). */
  bool get(const uint8_t, std::shared_ptr<pfcp::pfcp_mar>&) const;

  //------------------------------------------------------------------------------
  /** @brief Get the allocated uplink F-TEID (thread-safe). */
  bool get(pfcp::fteid_t& fteid);

  //------------------------------------------------------------------------------
  /** @brief Return the PDN type for this session. */
  pfcp::pdn_type_value_e get_pdn_type();

  // ---- Update (3GPP TS 29.244 §7.5.4) -------------------------------------

  //------------------------------------------------------------------------------
  /** @brief Apply an Update FAR IE (Table 7.5.4.3-1). */
  bool update(const pfcp::update_far& update, uint8_t& cause_value);

  /** @brief Apply an Update PDR IE (Table 7.5.4.2-1). */
  bool update(const pfcp::update_pdr& update, uint8_t& cause_value);

  /** @brief Apply an Update QER IE (Table 7.5.4.5-1). */
  bool update(const pfcp::update_qer& update, uint8_t& cause_value);

  /** @brief Apply an Update URR IE (Table 7.5.4.4-1). */
  bool update(const pfcp::update_urr& update, uint8_t& cause_value);

  /** @brief Apply an Update BAR IE (Table 7.5.4.11-1). */
  bool update(
      const pfcp::update_bar_within_pfcp_session_modification_request& update,
      uint8_t& cause_value);

  /** @brief Apply an Update MAR IE (Table 7.5.4.16-1). */
  bool update(const pfcp::update_mar& update, uint8_t& cause_value);

  // ---- Create (3GPP TS 29.244 §7.5.2) -------------------------------------

  //------------------------------------------------------------------------------
  /** @brief Process a Create FAR IE (Table 7.5.2.3-1). */
  bool create(
      const pfcp::create_far& cr_far, pfcp::cause_t& cause,
      uint16_t& offending_ie);

  /** @brief Process a Create PDR IE (Table 7.5.2.2-1); allocates F-TEID. */
  bool create(
      const pfcp::create_pdr& cr_pdr, pfcp::cause_t& cause,
      uint16_t& offending_ie, pfcp::fteid_t& allocated_fteid);

  /** @brief Process a Create QER IE (Table 7.5.2.5-1). */
  bool create(
      const pfcp::create_qer& cr_qer, pfcp::cause_t& cause,
      uint16_t& offending_ie);

  /** @brief Process a Create URR IE (Table 7.5.2.4-1). */
  bool create(
      const pfcp::create_urr& cr_urr, pfcp::cause_t& cause,
      uint16_t& offending_ie);

  /** @brief Process a Create BAR IE (Table 7.5.2.6-1). */
  bool create(
      const pfcp::create_bar& cr_bar, pfcp::cause_t& cause,
      uint16_t& offending_ie);

  /** @brief Process a Create MAR IE (Table 7.5.2.8-1). */
  bool create(
      const pfcp::create_mar& cr_mar, pfcp::cause_t& cause,
      uint16_t& offending_ie);

  // ---- Remove (3GPP TS 29.244 §7.5.4) -------------------------------------

  //------------------------------------------------------------------------------
  /** @brief Process a Remove FAR IE (Table 7.5.4.7-1). */
  bool remove(
      const pfcp::remove_far& rm_far, pfcp::cause_t& cause,
      uint16_t& offending_ie);

  /** @brief Process a Remove PDR IE (Table 7.5.4.6-1). */
  bool remove(
      const pfcp::remove_pdr& rm_pdr, pfcp::cause_t& cause,
      uint16_t& offending_ie);

  /** @brief Process a Remove QER IE (Table 7.5.4.9-1). */
  bool remove(
      const pfcp::remove_qer& rm_qer, pfcp::cause_t& cause,
      uint16_t& offending_ie);

  /** @brief Process a Remove URR IE (Table 7.5.4.8-1). */
  bool remove(
      const pfcp::remove_urr& rm_urr, pfcp::cause_t& cause,
      uint16_t& offending_ie);

  /** @brief Process a Remove BAR IE (Table 7.5.4.12-1). */
  bool remove(
      const pfcp::remove_bar& rm_bar, pfcp::cause_t& cause,
      uint16_t& offending_ie);

  /** @brief Process a Remove MAR IE (Table 7.5.4.15-1).
   *  TODO MAR: re-enable when common-src adds pfcp::remove_mar. Matches the
   *  #if 0 guards on the call sites in SessionManager.cpp / pfcp_switch.cpp. */
  bool remove(
      const pfcp::remove_mar& rm_mar, pfcp::cause_t& cause,
      uint16_t& offending_ie);
};
}  // namespace pfcp
#endif  // FILE_PFCP_SESSION_HPP_SEEN
