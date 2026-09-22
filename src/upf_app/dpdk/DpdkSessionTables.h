/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DPDK_SESSION_TABLES_H_
#define DPDK_SESSION_TABLES_H_

#include <rte_hash.h>
#include <rte_rcu_qsbr.h>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "IDatapathBackend.h"
#include "RuleConverter.h"

/**
 * @struct DpdkSessionRules
 * @brief One session's rules, flattened for the fast path.
 *
 * Built on the N4 thread and never modified afterwards: a change produces a
 * new instance that replaces the published pointer, and the old one is freed
 * once every lcore has passed a quiescent state. Lcores therefore read it
 * without locking.
 *
 * PDRs are split by direction and sorted by ascending precedence, so matching
 * is a linear scan that stops at the first hit (§8.2.11).
 */
struct DpdkSessionRules {
  uint64_t seid    = 0;
  uint32_t ue_ipv4 = 0;  ///< Network byte order; 0 when the session has none

  std::vector<struct pfcp_pdr> uplink_pdrs;    ///< ACCESS PDRs, by precedence
  std::vector<struct pfcp_pdr> downlink_pdrs;  ///< CORE PDRs, by precedence
  std::vector<struct pfcp_far> fars;
  std::vector<struct pfcp_qer> qers;
  std::vector<struct pfcp_urr> urrs;

  /// Traffic counters, updated by the lcores (per session, both directions).
  struct {
    uint64_t uplink_packets   = 0;
    uint64_t uplink_bytes     = 0;
    uint64_t downlink_packets = 0;
    uint64_t downlink_bytes   = 0;
  } stats;

  [[nodiscard]] const struct pfcp_far* FindFar(uint32_t far_id) const;
  [[nodiscard]] const struct pfcp_qer* FindQer(uint32_t qer_id) const;
};

/**
 * @class DpdkSessionTables
 * @brief The tables the lcores read, and the IDatapathBackend that fills them.
 *
 * Two lookups, both keyed on a single 32-bit value:
 *   - uplink:   GTP-U TEID       → session rules
 *   - downlink: UE IPv4 address  → session rules
 *
 * Writers (the N4 thread) publish a new rule set and then wait for an RCU
 * grace period before releasing the old one; readers (lcores) never block.
 * Every lcore must call ReportQuiescent() regularly, otherwise a writer
 * waits forever.
 */
class DpdkSessionTables : public IDatapathBackend {
 public:
  DpdkSessionTables();
  ~DpdkSessionTables() override;

  DpdkSessionTables(const DpdkSessionTables&) = delete;
  DpdkSessionTables& operator=(const DpdkSessionTables&) = delete;

  /**
   * @brief Create the hash tables and the RCU state.
   * @param max_sessions Capacity, from upf.datapath_configuration.
   * @param max_lcores   Lcores that will read the tables.
   * @throws std::runtime_error if a table cannot be created.
   */
  void Setup(uint32_t max_sessions, uint32_t max_lcores);

  /// Free every table and rule set. Idempotent.
  void TearDown();

  // ---- IDatapathBackend (N4 thread) ---------------------------------------

  void CreatePipeline(std::shared_ptr<pfcp::pfcp_session> session) override;
  void ModifyPipeline(std::shared_ptr<pfcp::pfcp_session> session) override;
  void RemovePipeline(uint64_t seid) override;

  void RemoveAllSessions();

  // ---- Fast path (lcores, lock-free) --------------------------------------

  /// Uplink lookup by GTP-U TEID (host byte order).
  [[nodiscard]] DpdkSessionRules* LookupByTeid(uint32_t teid) const;

  /// Downlink lookup by UE IPv4 address (network byte order).
  [[nodiscard]] DpdkSessionRules* LookupByUeIp(uint32_t ue_ipv4) const;

  /// Register a reader lcore; @p reader_id must be unique and < max_lcores.
  void RegisterReader(unsigned reader_id) const;

  /// Announce that this lcore holds no reference to a rule set any more.
  void ReportQuiescent(unsigned reader_id) const;

  /**
   * @brief Retire a reader lcore.
   *
   * A worker must call this before it stops polling: writers wait for every
   * registered reader, so one that never reports again blocks reclamation,
   * and with it shutdown.
   */
  void UnregisterReader(unsigned reader_id) const;

  [[nodiscard]] size_t GetSessionCount() const;

 private:
  /// Flatten a session into the fast-path form (N4 thread).
  std::unique_ptr<DpdkSessionRules> BuildRules(
      const std::shared_ptr<pfcp::pfcp_session>& session) const;

  /// Publish the TEID / UE-IP keys of @p rules.
  void PublishKeys(DpdkSessionRules* rules);

  /// Withdraw the keys of @p rules.
  void WithdrawKeys(const DpdkSessionRules* rules);

  /// Wait for every reader to release the retired rule sets, then free them.
  void ReclaimRetired();

  mutable std::mutex mutex_;  ///< Serialises writers; readers never take it.
  rte_hash* teid_table_ = nullptr;
  rte_hash* ueip_table_ = nullptr;
  rte_rcu_qsbr* qsbr_   = nullptr;

  std::map<uint64_t, std::unique_ptr<DpdkSessionRules>> sessions_;
  std::vector<std::unique_ptr<DpdkSessionRules>> retired_;
  uint32_t max_lcores_ = 0;
  bool is_setup_       = false;
};

#endif  // DPDK_SESSION_TABLES_H_
