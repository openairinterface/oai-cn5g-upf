/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DpdkSessionTables.h"

#include <rte_errno.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

#include <algorithm>
#include <stdexcept>

#include "logger.hpp"
#include "pfcp_session.hpp"

namespace {

/// 3GPP TS 29.244 §8.2.2 — Source Interface values used to split directions.
constexpr uint8_t kSourceInterfaceAccess = 0;
constexpr uint8_t kSourceInterfaceCore   = 1;

rte_hash* CreateTable(const char* name, uint32_t entries) {
  rte_hash_parameters params{};
  params.name       = name;
  params.entries    = entries;
  params.key_len    = sizeof(uint32_t);
  params.hash_func  = rte_jhash;
  params.socket_id  = SOCKET_ID_ANY;
  // Readers run without locks while the N4 thread updates the table.
  params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;

  rte_hash* table = rte_hash_create(&params);
  if (table == nullptr) {
    throw std::runtime_error(
        std::string("DPDK: cannot create the '") + name +
        "' table: " + rte_strerror(rte_errno));
  }
  return table;
}

}  // namespace

//------------------------------------------------------------------------------
const struct pfcp_far* DpdkSessionRules::FindFar(uint32_t far_id) const {
  for (const auto& far : fars) {
    if (far.far_id.far_id == far_id) return &far;
  }
  return nullptr;
}

//------------------------------------------------------------------------------
const struct pfcp_qer* DpdkSessionRules::FindQer(uint32_t qer_id) const {
  for (const auto& qer : qers) {
    if (qer.qer_id.qer_id == qer_id) return &qer;
  }
  return nullptr;
}

//------------------------------------------------------------------------------
DpdkSessionTables::DpdkSessionTables() {}

//------------------------------------------------------------------------------
DpdkSessionTables::~DpdkSessionTables() {
  TearDown();
}

//------------------------------------------------------------------------------
void DpdkSessionTables::Setup(uint32_t max_sessions, uint32_t max_lcores) {
  if (is_setup_) return;

  max_lcores_ = max_lcores;

  // One session can publish several TEIDs (one per uplink PDR), so the uplink
  // table gets room for a few keys per session.
  teid_table_ = CreateTable("upf_teid_sessions", max_sessions * 4);
  ueip_table_ = CreateTable("upf_ueip_sessions", max_sessions * 2);

  const size_t qsbr_size = rte_rcu_qsbr_get_memsize(max_lcores);
  qsbr_                  = static_cast<rte_rcu_qsbr*>(rte_zmalloc(
      "upf_qsbr", qsbr_size, RTE_CACHE_LINE_SIZE));
  if (qsbr_ == nullptr) {
    throw std::runtime_error("DPDK: cannot allocate the RCU QSBR variable");
  }
  if (rte_rcu_qsbr_init(qsbr_, max_lcores) != 0) {
    throw std::runtime_error("DPDK: cannot initialise the RCU QSBR variable");
  }

  // Let the hash defer the reuse of freed key slots until readers are done.
  rte_hash_rcu_config rcu_config{};
  rcu_config.v    = qsbr_;
  rcu_config.mode = RTE_HASH_QSBR_MODE_DQ;
  if (rte_hash_rcu_qsbr_add(teid_table_, &rcu_config) != 0 ||
      rte_hash_rcu_qsbr_add(ueip_table_, &rcu_config) != 0) {
    throw std::runtime_error(
        "DPDK: cannot attach the RCU QSBR variable to the session tables");
  }

  is_setup_ = true;
  Logger::upf_app().info(
      "DPDK: session tables ready for %u sessions and %u reader lcore(s)",
      max_sessions, max_lcores);
}

//------------------------------------------------------------------------------
void DpdkSessionTables::TearDown() {
  if (!is_setup_) return;

  RemoveAllSessions();

  if (teid_table_ != nullptr) {
    rte_hash_free(teid_table_);
    teid_table_ = nullptr;
  }
  if (ueip_table_ != nullptr) {
    rte_hash_free(ueip_table_);
    ueip_table_ = nullptr;
  }
  if (qsbr_ != nullptr) {
    rte_free(qsbr_);
    qsbr_ = nullptr;
  }
  is_setup_ = false;
}

//------------------------------------------------------------------------------
void DpdkSessionTables::RegisterReader(unsigned reader_id) const {
  if (qsbr_ == nullptr) return;
  rte_rcu_qsbr_thread_register(qsbr_, reader_id);
  rte_rcu_qsbr_thread_online(qsbr_, reader_id);
}

//------------------------------------------------------------------------------
void DpdkSessionTables::ReportQuiescent(unsigned reader_id) const {
  if (qsbr_ == nullptr) return;
  rte_rcu_qsbr_quiescent(qsbr_, reader_id);
}

//------------------------------------------------------------------------------
void DpdkSessionTables::UnregisterReader(unsigned reader_id) const {
  if (qsbr_ == nullptr) return;
  rte_rcu_qsbr_thread_offline(qsbr_, reader_id);
  rte_rcu_qsbr_thread_unregister(qsbr_, reader_id);
}

//------------------------------------------------------------------------------
std::unique_ptr<DpdkSessionRules> DpdkSessionTables::BuildRules(
    const std::shared_ptr<pfcp::pfcp_session>& session) const {
  auto built  = std::make_unique<DpdkSessionRules>();
  built->seid = session->get_up_seid();

  for (const auto& pdr : session->pdrs) {
    const struct pfcp_pdr flat = rules::ConvertPdr(pdr);

    switch (flat.pdi.source_interface.interface_value) {
      case kSourceInterfaceAccess:
        built->uplink_pdrs.push_back(flat);
        break;
      case kSourceInterfaceCore:
        built->downlink_pdrs.push_back(flat);
        // rules::ConvertPdr copies the address but not the v4/v6 flags, so a
        // non-zero address is what tells us the PDI carries a UE IPv4.
        if (flat.pdi.ue_ip_address.ipv4_address.s_addr != 0) {
          built->ue_ipv4 = flat.pdi.ue_ip_address.ipv4_address.s_addr;
        }
        break;
      default:
        Logger::upf_app().warn(
            "DPDK: PDR %u of session 0x%lx has an unsupported source "
            "interface %u; ignoring it",
            flat.pdr_id.rule_id, built->seid,
            flat.pdi.source_interface.interface_value);
        break;
    }
  }

  // Lowest precedence value wins, so the fast path stops at the first match.
  const auto by_precedence = [](const struct pfcp_pdr& left,
                                const struct pfcp_pdr& right) {
    return left.precedence.precedence < right.precedence.precedence;
  };
  std::sort(
      built->uplink_pdrs.begin(), built->uplink_pdrs.end(), by_precedence);
  std::sort(
      built->downlink_pdrs.begin(), built->downlink_pdrs.end(), by_precedence);

  for (const auto& far : session->fars) {
    built->fars.push_back(rules::ConvertFar(far));
  }
  for (const auto& qer : session->qers) {
    built->qers.push_back(rules::ConvertQer(qer));
  }
  for (const auto& urr : session->urrs) {
    built->urrs.push_back(rules::ConvertUrr(urr));
  }

  return built;
}

//------------------------------------------------------------------------------
void DpdkSessionTables::PublishKeys(DpdkSessionRules* rules) {
  for (const auto& pdr : rules->uplink_pdrs) {
    const uint32_t teid = pdr.pdi.fteid.teid;
    if (teid == 0) continue;
    if (rte_hash_add_key_data(teid_table_, &teid, rules) < 0) {
      Logger::upf_app().error(
          "DPDK: cannot publish TEID 0x%x of session 0x%lx", teid,
          rules->seid);
    }
  }

  if (rules->ue_ipv4 != 0) {
    if (rte_hash_add_key_data(ueip_table_, &rules->ue_ipv4, rules) < 0) {
      Logger::upf_app().error(
          "DPDK: cannot publish the UE IP of session 0x%lx", rules->seid);
    }
  }
}

//------------------------------------------------------------------------------
void DpdkSessionTables::WithdrawKeys(const DpdkSessionRules* rules) {
  for (const auto& pdr : rules->uplink_pdrs) {
    const uint32_t teid = pdr.pdi.fteid.teid;
    if (teid != 0) rte_hash_del_key(teid_table_, &teid);
  }
  if (rules->ue_ipv4 != 0) {
    rte_hash_del_key(ueip_table_, &rules->ue_ipv4);
  }
}

//------------------------------------------------------------------------------
void DpdkSessionTables::ReclaimRetired() {
  if (retired_.empty()) return;

  // Blocks until every registered lcore has reported a quiescent state, so no
  // lcore can still be reading the rule sets we are about to free.
  rte_rcu_qsbr_synchronize(qsbr_, RTE_QSBR_THRID_INVALID);
  retired_.clear();
}

//------------------------------------------------------------------------------
void DpdkSessionTables::CreatePipeline(
    std::shared_ptr<pfcp::pfcp_session> session) {
  if (!session) return;
  if (!is_setup_) {
    Logger::upf_app().error(
        "DPDK: session tables are not set up; dropping session 0x%lx",
        session->get_up_seid());
    return;
  }

  std::unique_ptr<DpdkSessionRules> built = BuildRules(session);
  DpdkSessionRules* published             = built.get();
  const uint64_t seid                     = built->seid;

  std::lock_guard<std::mutex> lock(mutex_);

  auto existing = sessions_.find(seid);
  if (existing != sessions_.end()) {
    Logger::upf_app().warn(
        "DPDK: session 0x%lx already installed; replacing it", seid);
    WithdrawKeys(existing->second.get());
    retired_.push_back(std::move(existing->second));
    sessions_.erase(existing);
  }

  sessions_[seid] = std::move(built);
  PublishKeys(published);
  ReclaimRetired();

  Logger::upf_app().info(
      "DPDK: session 0x%lx installed — %zu uplink PDR(s), %zu downlink PDR(s), "
      "%zu FAR(s), %zu QER(s)",
      seid, published->uplink_pdrs.size(), published->downlink_pdrs.size(),
      published->fars.size(), published->qers.size());
}

//------------------------------------------------------------------------------
void DpdkSessionTables::ModifyPipeline(
    std::shared_ptr<pfcp::pfcp_session> session) {
  if (!session) return;
  if (!is_setup_) return;

  // A modification is a fresh rule set that replaces the published one; the
  // old set lives until every lcore has let go of it.
  std::unique_ptr<DpdkSessionRules> built = BuildRules(session);
  DpdkSessionRules* published             = built.get();
  const uint64_t seid                     = built->seid;

  std::lock_guard<std::mutex> lock(mutex_);

  auto existing = sessions_.find(seid);
  if (existing != sessions_.end()) {
    // Carry the traffic counters over: a modification is not a new session.
    published->stats = existing->second->stats;
    WithdrawKeys(existing->second.get());
    retired_.push_back(std::move(existing->second));
    sessions_.erase(existing);
  } else {
    Logger::upf_app().warn(
        "DPDK: modification for unknown session 0x%lx; installing it", seid);
  }

  sessions_[seid] = std::move(built);
  PublishKeys(published);
  ReclaimRetired();

  Logger::upf_app().info("DPDK: session 0x%lx updated", seid);
}

//------------------------------------------------------------------------------
void DpdkSessionTables::RemovePipeline(uint64_t seid) {
  if (!is_setup_) return;

  std::lock_guard<std::mutex> lock(mutex_);

  auto existing = sessions_.find(seid);
  if (existing == sessions_.end()) {
    Logger::upf_app().warn("DPDK: cannot remove unknown session 0x%lx", seid);
    return;
  }

  WithdrawKeys(existing->second.get());
  retired_.push_back(std::move(existing->second));
  sessions_.erase(existing);
  ReclaimRetired();

  Logger::upf_app().info("DPDK: session 0x%lx removed", seid);
}

//------------------------------------------------------------------------------
void DpdkSessionTables::RemoveAllSessions() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (sessions_.empty()) return;

  Logger::upf_app().info(
      "DPDK: removing %zu installed session(s)", sessions_.size());

  for (auto& entry : sessions_) {
    WithdrawKeys(entry.second.get());
    retired_.push_back(std::move(entry.second));
  }
  sessions_.clear();
  ReclaimRetired();
}

//------------------------------------------------------------------------------
DpdkSessionRules* DpdkSessionTables::LookupByTeid(uint32_t teid) const {
  void* data = nullptr;
  if (rte_hash_lookup_data(teid_table_, &teid, &data) < 0) return nullptr;
  return static_cast<DpdkSessionRules*>(data);
}

//------------------------------------------------------------------------------
DpdkSessionRules* DpdkSessionTables::LookupByUeIp(uint32_t ue_ipv4) const {
  void* data = nullptr;
  if (rte_hash_lookup_data(ueip_table_, &ue_ipv4, &data) < 0) return nullptr;
  return static_cast<DpdkSessionRules*>(data);
}

//------------------------------------------------------------------------------
size_t DpdkSessionTables::GetSessionCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return sessions_.size();
}
