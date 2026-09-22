/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef I_DATAPATH_BACKEND_H_
#define I_DATAPATH_BACKEND_H_

#include <cstdint>
#include <memory>

namespace pfcp {
class pfcp_session;
}  // namespace pfcp

/**
 * @class IDatapathBackend
 * @brief Seam between SessionManager (PFCP session bookkeeping) and the
 *        component that programs the packet-processing datapath.
 *
 * SessionManager keeps the authoritative per-session PDR/FAR/QER/URR/BAR/MAR
 * state and calls into the backend whenever the datapath must reflect it.
 * Implementations:
 *   - SessionProgramManager — eBPF/XDP flavour (writes BPF maps)
 *   - DpdkSessionTables     — DPDK flavour (writes lcore-visible tables)
 *
 * The session passed in is a snapshot owned by the caller; backends must copy
 * whatever they need and must not keep references into it.
 *
 * Methods are called from the N4 (ITTI) thread, never from a fast-path thread.
 */
class IDatapathBackend {
 public:
  virtual ~IDatapathBackend() = default;

  /// Install every rule of a newly established session (TS 29.244 §7.5.2).
  virtual void CreatePipeline(std::shared_ptr<pfcp::pfcp_session> session) = 0;

  /// Re-sync the datapath with a modified session (TS 29.244 §7.5.4).
  virtual void ModifyPipeline(std::shared_ptr<pfcp::pfcp_session> session) = 0;

  /// Remove every datapath entry of a session (TS 29.244 §7.5.6).
  virtual void RemovePipeline(uint64_t seid) = 0;
};

#endif  // I_DATAPATH_BACKEND_H_
