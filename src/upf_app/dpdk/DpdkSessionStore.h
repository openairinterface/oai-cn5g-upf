/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DPDK_SESSION_STORE_H_
#define DPDK_SESSION_STORE_H_

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "session/ISessionRegistry.h"
#include "uint_generator.hpp"

namespace pfcp {
class pfcp_session;
}  // namespace pfcp

/**
 * @class DpdkSessionStore
 * @brief Session bookkeeping for the DPDK flavour: identifier allocation and
 *        the CP F-SEID / UP SEID indexes used by the N4 handlers.
 *
 * It deliberately keeps no PDR lookup index. The tables the lcores read are
 * built from the complete session by DpdkSessionTables, so a PDR index here
 * would be a second source of truth for the same thing. The
 * Register/Unregister hooks of ISessionRegistry are therefore no-ops.
 *
 * All access is from the N4 (ITTI) thread; the mutex guards against the
 * datapath backend reading concurrently.
 */
class DpdkSessionStore : public ISessionRegistry {
 public:
  DpdkSessionStore()           = default;
  ~DpdkSessionStore() override = default;

  DpdkSessionStore(const DpdkSessionStore&) = delete;
  DpdkSessionStore& operator=(const DpdkSessionStore&) = delete;

  // ---- Identifier allocation ----------------------------------------------

  /// Allocate a UP SEID (TS 29.244 §8.2.37).
  uint64_t GenerateSeid() { return seid_generator_.get_uid(); }

  // ---- Session index ------------------------------------------------------

  void AddSession(std::shared_ptr<pfcp::pfcp_session> session);
  std::shared_ptr<pfcp::pfcp_session> FindByUpSeid(uint64_t seid) const;
  std::shared_ptr<pfcp::pfcp_session> FindByCpFseid(
      const pfcp::fseid_t& cp_fseid) const;
  /// Remove a session from both indexes; returns it, or nullptr if unknown.
  std::shared_ptr<pfcp::pfcp_session> RemoveByUpSeid(uint64_t seid);
  std::vector<std::shared_ptr<pfcp::pfcp_session>> GetAllSessions() const;
  size_t GetSessionCount() const;

  // ---- ISessionRegistry ---------------------------------------------------

  pfcp::fteid_t AllocateN3Fteid() override;

  bool RegisterUplinkPdr(
      std::shared_ptr<pfcp::pfcp_pdr>& pdr, const pfcp::fteid_t& fteid,
      uint8_t& cause) override;

  void RegisterDownlinkPdr(
      uint32_t ue_ipv4_hbo, std::shared_ptr<pfcp::pfcp_pdr>& pdr) override;

  void UnregisterUplinkPdr(uint32_t teid) override;

  void UnregisterDownlinkPdr(uint32_t ue_ipv4_hbo) override;

 private:
  mutable std::mutex mutex_;
  std::map<uint64_t, std::shared_ptr<pfcp::pfcp_session>> up_seid_to_session_;
  std::map<uint64_t, uint64_t> cp_seid_to_up_seid_;

  oai::utils::uint_generator<uint64_t> seid_generator_;
  oai::utils::uint_generator<uint32_t> teid_n3_generator_;
};

#endif  // DPDK_SESSION_STORE_H_
