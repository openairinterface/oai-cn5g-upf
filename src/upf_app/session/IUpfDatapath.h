/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef I_UPF_DATAPATH_H_
#define I_UPF_DATAPATH_H_

#include <memory>

#include "itti_msg_n4.hpp"

namespace pfcp {
class pfcp_session;
}  // namespace pfcp

/**
 * @class IUpfDatapath
 * @brief The N4 boundary: what upf_app asks of a datapath flavour.
 *
 * upf_app receives N4 messages over ITTI and knows nothing about how packets
 * are forwarded. Each flavour provides one implementation:
 *   - LegacySwitchDatapath — simple-switch and eBPF (delegates to pfcp_switch)
 *   - DpdkDatapath         — DPDK
 *
 * All methods run on the TASK_UPF_APP (ITTI) thread; implementations do not
 * need to be thread-safe against each other, but must be against their own
 * fast path.
 *
 * @see 3GPP TS 29.244 §7.5 — N4 session procedures
 */
class IUpfDatapath {
 public:
  virtual ~IUpfDatapath() = default;

  /// PFCP Session Establishment (§7.5.2): fills @p response.
  virtual void HandleSessionEstablishment(
      std::shared_ptr<itti_n4_session_establishment_request> request,
      itti_n4_session_establishment_response* response) = 0;

  /// PFCP Session Modification (§7.5.4): fills @p response.
  virtual void HandleSessionModification(
      std::shared_ptr<itti_n4_session_modification_request> request,
      itti_n4_session_modification_response* response) = 0;

  /// PFCP Session Deletion (§7.5.6): fills @p response.
  virtual void HandleSessionDeletion(
      std::shared_ptr<itti_n4_session_deletion_request> request,
      itti_n4_session_deletion_response* response) = 0;

  /// Drop a session without an N4 exchange (PFCP association teardown, §6.2.6).
  virtual void RemoveSession(const pfcp::fseid_t& cp_fseid) = 0;
};

#endif  // I_UPF_DATAPATH_H_
