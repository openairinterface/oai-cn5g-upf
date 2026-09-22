/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DPDK_DATAPATH_H_
#define DPDK_DATAPATH_H_

#include <memory>

#include "session/IUpfDatapath.h"

class DpdkFastPath;
class DpdkSessionStore;
class DpdkSessionTables;
class SessionManager;

/**
 * @class DpdkDatapath
 * @brief The DPDK flavour of the UPF user plane.
 *
 * Owns the whole flavour and nothing outside it:
 *   - DpdkSessionStore  — identifier allocation and the session index, and the
 *                         ISessionRegistry the PFCP session model talks to
 *   - SessionManager    — rule state and Update/Remove IE handling (shared,
 *                         flavour-neutral)
 *   - DpdkSessionTables — IDatapathBackend: the tables the lcores read
 *
 * It implements IUpfDatapath, so upf_app drives it exactly as it drives the
 * other flavours, with no pfcp_switch involved.
 *
 * Still to come: EAL init, port/queue/mempool setup, lcore launch, and the
 * exception path for ARP/ND and GTP-U echo.
 *
 * @note rte_eal_init() re-pins the calling thread. Once EAL init is added it
 *       must run from main() before ITTI and the other control threads are
 *       spawned, otherwise they inherit the main-lcore affinity.
 */
class DpdkDatapath : public IUpfDatapath {
 public:
  DpdkDatapath();
  ~DpdkDatapath() override;

  DpdkDatapath(const DpdkDatapath&) = delete;
  DpdkDatapath& operator=(const DpdkDatapath&) = delete;

  /**
   * @brief Build the flavour and start forwarding.
   *
   * Configures the ports, sizes the session tables, and launches one worker
   * per polling lcore. EAL must already be initialised (DpdkEal::Init).
   *
   * @throws std::runtime_error if a device or an lcore cannot be set up.
   */
  void Setup();

  /// Log the port counters and what each worker has seen.
  void LogStatistics() const;

  /// Remove all sessions and release DPDK resources. Idempotent.
  void TearDown();

  // ---- IUpfDatapath (3GPP TS 29.244 §7.5) ---------------------------------

  void HandleSessionEstablishment(
      std::shared_ptr<itti_n4_session_establishment_request> request,
      itti_n4_session_establishment_response* response) override;

  void HandleSessionModification(
      std::shared_ptr<itti_n4_session_modification_request> request,
      itti_n4_session_modification_response* response) override;

  void HandleSessionDeletion(
      std::shared_ptr<itti_n4_session_deletion_request> request,
      itti_n4_session_deletion_response* response) override;

  void RemoveSession(const pfcp::fseid_t& cp_fseid) override;

  std::shared_ptr<SessionManager> GetSessionManager() const {
    return session_manager_;
  }

 private:
  /**
   * @brief Apply the Create PDR/FAR/QER/URR/BAR/MAR IEs of a request.
   *
   * Shared by establishment (§7.5.2) and modification (§7.5.4): both carry the
   * same grouped IEs. FARs are created before PDRs because a Create PDR refers
   * to its FAR by ID. Created PDRs (with any allocated N3 F-TEID) are reported
   * back through @p response.
   *
   * @return false if a mandatory/conditional IE was missing or a rule was
   *         rejected; @p cause and @p offending_ie then describe why.
   */
  template <typename RequestIes, typename ResponseMsg>
  bool ApplyCreateIes(
      pfcp::pfcp_session* session, RequestIes& ies, ResponseMsg* response,
      pfcp::cause_t& cause, pfcp::offending_ie_t& offending_ie);

  /// Push the current session state to the datapath backend.
  void SyncDatapath(
      pfcp::pfcp_session* session,
      itti_n4_session_establishment_request* establishment,
      itti_n4_session_modification_request* modification,
      itti_n4_session_deletion_request* deletion);

  std::shared_ptr<DpdkSessionStore> session_store_;
  std::shared_ptr<DpdkSessionTables> session_tables_;
  std::shared_ptr<SessionManager> session_manager_;
  std::unique_ptr<DpdkFastPath> fast_path_;
  bool is_setup_ = false;
};

#endif  // DPDK_DATAPATH_H_
