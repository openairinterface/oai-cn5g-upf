/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef SESSION_LOOKUP_ETH_USER_H_
#define SESSION_LOOKUP_ETH_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <xdp_session_lookup_eth_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using SessionLookupETHLifeCycle =
    ProgramLifeCycle<xdp_session_lookup_eth_kern_c>;

/**
 * @class SessionLookupETHProgram
 * @brief Manages the xdp_session_lookup_eth XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * SessionLookupIPProgram. ETH PDU counterpart. Instantiated by
 * UPF_XDPProgram only when pdu_type == Ethernet.
 *
 * Lifecycle (orchestrated by UPF_XDPProgram):
 *   1. Constructor  -- creates lifecycle_, does NOT open skeleton.
 *   2. UPF_XDPProgram calls GetLifeCycle()->open() to get the bpf_object
 *      before ShareMaps().
 *   3. UPF_XDPProgram::ShareMaps(primary, this) -- reuse_fd for shared
 *      tail_call maps. Primary = n3_eth_ (ETH PDU).
 *   4. Setup()      -- InitializeMaps() + load() (no attach, no link).
 *   5. TearDown()   -- lifecycle_->tearDown().
 */
class SessionLookupETHProgram : public BPFProgram {
 public:
  /** @brief Constructor -- creates lifecycle_, does NOT open skeleton. */
  SessionLookupETHProgram();

  /** @brief Destructor. */
  virtual ~SessionLookupETHProgram();

  /**
   * @brief Initialize maps and load the XDP program into the kernel.
   *
   * Order: lifecycle_->open() (idempotent) -> InitializeMaps() -> load().
   * Must be called AFTER UPF_XDPProgram::ShareMaps() has reused the
   * tail_call map FDs from the primary (n3_eth_entry) skeleton.
   * No attach() or link() -- stage programs are reached via tail call only.
   */
  void Setup();

  /**
   * @brief Unload the XDP program.
   *
   * Delegates to lifecycle_->tearDown().
   */
  void TearDown();

  /**
   * @brief Returns the lifecycle for external orchestration.
   *
   * UPF_XDPProgram uses this to call open() before ShareMaps().
   */
  std::shared_ptr<SessionLookupETHLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /**
   * @brief Returns the raw bpf_object_skeleton pointer.
   *
   * Used by BPFMaps construction by orchestrator.
   */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns the xdp_program* for insertion into tail_call_progs_map.
   *
   * Called by UPF_XDPProgram::InsertProgramSlot(PROG_SESSION_LOOKUP_ETH, ...).
   */
  struct bpf_program* GetXdpProgram() const;

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps() const;

  /** @name Direct map accessors (eth_pdu_maps.h) */
  ///@{
  std::shared_ptr<BPFMap> GetSessionByMacMap() const;
  std::shared_ptr<BPFMap> GetEthSessionMappingMap() const;
  std::shared_ptr<BPFMap> GetEthSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetEthRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> GetEthEgressIfindexMap() const;
  std::shared_ptr<BPFMap> GetMacPduSessionMap() const;
  ///@}

  /** @name Direct map accessors (pipeline_maps.h -- shared) */
  ///@{
  std::shared_ptr<BPFMap> GetFeatureDispatchMap() const;
  ///@}

  /** @name Direct map accessors (tail_call_dispatcher.h -- shared) */
  ///@{
  std::shared_ptr<BPFMap> GetTailCallProgsMap() const;
  std::shared_ptr<BPFMap> GetPacketContextMap() const;
  std::shared_ptr<BPFMap> GetSessionRulesEnabledMap() const;
  ///@}

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

 private:
  /**
   * @brief Configure max_entries for all runtime-sized maps.
   *
   * Uses ConfigureMapMaxEntries(skel->maps.field, "name", size).
   * Called inside the open_fn lambda before the skeleton is returned.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_session_lookup_eth_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   *
   * Called from Setup() so that map pointers are valid before load.
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_session_lookup_eth_kern_c* skeleton_ = nullptr;
  std::shared_ptr<SessionLookupETHLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Maps -- eth_pdu_maps.h
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> session_by_mac_map_;
  std::shared_ptr<BPFMap> eth_session_mapping_map_;
  std::shared_ptr<BPFMap> eth_session_pdrs_map_;
  std::shared_ptr<BPFMap> eth_rules_match_pdr_map_;
  std::shared_ptr<BPFMap> eth_egress_ifindex_map_;
  std::shared_ptr<BPFMap> mac_pdu_session_map_;
  //----------------------------------------------------------------------------
  // Maps -- pipeline_maps.h (shared from primary via reuse_fd)
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMap> feature_dispatch_map_;
  //----------------------------------------------------------------------------
  // Maps -- tail_call_dispatcher.h (shared from primary via reuse_fd)
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMap> tail_call_progs_map_;
  std::shared_ptr<BPFMap> packet_ctx_map_;
  std::shared_ptr<BPFMap> session_rules_enabled_map_;
};

#endif /* SESSION_LOOKUP_ETH_USER_H_ */
