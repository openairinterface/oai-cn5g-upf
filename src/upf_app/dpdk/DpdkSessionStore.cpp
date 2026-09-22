/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DpdkSessionStore.h"

#include "logger.hpp"
#include "pfcp_session.hpp"
#include "upf_config.hpp"

extern oai::config::upf_config upf_cfg;

//------------------------------------------------------------------------------
void DpdkSessionStore::AddSession(
    std::shared_ptr<pfcp::pfcp_session> session) {
  if (!session) return;
  std::lock_guard<std::mutex> lock(mutex_);
  up_seid_to_session_[session->seid]          = session;
  cp_seid_to_up_seid_[session->cp_fseid.seid] = session->seid;
}

//------------------------------------------------------------------------------
std::shared_ptr<pfcp::pfcp_session> DpdkSessionStore::FindByUpSeid(
    uint64_t seid) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = up_seid_to_session_.find(seid);
  return it == up_seid_to_session_.end() ? nullptr : it->second;
}

//------------------------------------------------------------------------------
std::shared_ptr<pfcp::pfcp_session> DpdkSessionStore::FindByCpFseid(
    const pfcp::fseid_t& cp_fseid) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = cp_seid_to_up_seid_.find(cp_fseid.seid);
  if (it == cp_seid_to_up_seid_.end()) return nullptr;
  auto session = up_seid_to_session_.find(it->second);
  return session == up_seid_to_session_.end() ? nullptr : session->second;
}

//------------------------------------------------------------------------------
std::shared_ptr<pfcp::pfcp_session> DpdkSessionStore::RemoveByUpSeid(
    uint64_t seid) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = up_seid_to_session_.find(seid);
  if (it == up_seid_to_session_.end()) return nullptr;

  std::shared_ptr<pfcp::pfcp_session> session = it->second;
  cp_seid_to_up_seid_.erase(session->cp_fseid.seid);
  up_seid_to_session_.erase(it);
  return session;
}

//------------------------------------------------------------------------------
std::vector<std::shared_ptr<pfcp::pfcp_session>>
DpdkSessionStore::GetAllSessions() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::shared_ptr<pfcp::pfcp_session>> sessions;
  sessions.reserve(up_seid_to_session_.size());
  for (const auto& entry : up_seid_to_session_) {
    sessions.push_back(entry.second);
  }
  return sessions;
}

//------------------------------------------------------------------------------
size_t DpdkSessionStore::GetSessionCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return up_seid_to_session_.size();
}

//------------------------------------------------------------------------------
// ISessionRegistry
//------------------------------------------------------------------------------

// N3 F-TEID allocation — TS 29.244 §8.2.3.
pfcp::fteid_t DpdkSessionStore::AllocateN3Fteid() {
  pfcp::fteid_t fteid = {};
  fteid.teid          = teid_n3_generator_.get_uid();
  if (upf_cfg.n3.addr4.s_addr) {
    fteid.v4                  = 1;
    fteid.ipv4_address.s_addr = upf_cfg.n3.addr4.s_addr;
  } else {
    fteid.v6           = 1;
    fteid.ipv6_address = upf_cfg.n3.addr6;
  }
  return fteid;
}

// The uplink/downlink lookup entries the lcores use are rebuilt from the whole
// session by DpdkSessionTables, so there is nothing to index here.

bool DpdkSessionStore::RegisterUplinkPdr(
    std::shared_ptr<pfcp::pfcp_pdr>& pdr, const pfcp::fteid_t& fteid,
    uint8_t& cause) {
  (void) pdr;
  Logger::upf_n4().debug(
      "DPDK: uplink PDR accepted for TEID " TEID_FMT, fteid.teid);
  cause = pfcp::CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}

void DpdkSessionStore::RegisterDownlinkPdr(
    uint32_t ue_ipv4_hbo, std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  (void) pdr;
  Logger::upf_n4().debug(
      "DPDK: downlink PDR accepted for UE IP %u.%u.%u.%u",
      (ue_ipv4_hbo >> 24) & 0xFF, (ue_ipv4_hbo >> 16) & 0xFF,
      (ue_ipv4_hbo >> 8) & 0xFF, ue_ipv4_hbo & 0xFF);
}

void DpdkSessionStore::UnregisterUplinkPdr(uint32_t teid) {
  (void) teid;
}

void DpdkSessionStore::UnregisterDownlinkPdr(uint32_t ue_ipv4_hbo) {
  (void) ue_ipv4_hbo;
}
