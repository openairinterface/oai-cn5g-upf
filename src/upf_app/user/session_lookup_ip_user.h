/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef SESSION_LOOKUP_IP_USER_H_
#define SESSION_LOOKUP_IP_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <xdp_session_lookup_ip_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using SessionLookupIPLifeCycle = ProgramLifeCycle<xdp_session_lookup_ip_kern_c>;

/**
 * @class SessionLookupIPProgram
 * @brief Manages the xdp_session_lookup_ip XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * N3EntryProgram. This is a STAGE program: it is loaded but never attached
 * or linked to an interface. It is invoked via tail call from the entry
 * programs on the IP PDU session data path.
 *
 * Lifecycle (orchestrated by UPF_XDPProgram):
 *   1. Constructor  -- creates lifecycle_, does NOT open skeleton.
 *   2. UPF_XDPProgram calls GetLifeCycle()->open() to get the bpf_object
 *      before ShareMaps().
 *   3. UPF_XDPProgram::ShareMaps(primary, this) -- reuse_fd for shared
 *      tail_call maps. Primary = n3_ (IP PDU) or n3_eth_ (ETH PDU).
 *   4. Setup()      -- InitializeMaps() + load() (no attach, no link).
 *   5. TearDown()   -- lifecycle_->tearDown().
 */
class SessionLookupIPProgram : public BPFProgram {
 public:
  /** @brief Constructor -- creates lifecycle_, does NOT open skeleton. */
  SessionLookupIPProgram();

  /** @brief Destructor. */
  virtual ~SessionLookupIPProgram();

  /**
   * @brief Initialize maps and load the XDP program into the kernel.
   *
   * Order: lifecycle_->open() (idempotent) → InitializeMaps() → load().
   * Must be called AFTER UPF_XDPProgram::ShareMaps() has reused the
   * tail_call map FDs from the primary (n3_entry) skeleton.
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
   * UPF_XDPProgram uses this to:
   *   - Call open() before ShareMaps() (GetBpfObject() requires open).
   *   - Implement IsNativeXdp() / GetXdpModeString() without entry programs
   *     needing these methods directly (resolves TODO 2 from
   * n3_entry_user.cpp).
   */
  std::shared_ptr<SessionLookupIPLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /**
   * @brief Returns the raw bpf_object_skeleton pointer.
   *
   * Used by BPFMaps construction:
   *   maps_ = std::make_shared<BPFMaps>(sl_ip_->GetSkeleton());
   */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns the xdp_program* for insertion into tail_call_progs_map.
   *
   * Called by UPF_XDPProgram::InsertProgramSlot(PROG_SESSION_LOOKUP_IP, ...).
   */
  struct bpf_program* GetXdpProgram() const;

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps() const;

  /** @name Direct map accessors (pipeline_maps.h) */
  ///@{
  std::shared_ptr<BPFMap> GetSessionByUeIpMap() const;
  std::shared_ptr<BPFMap> GetSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetSessionQosEnabledMap() const;
  std::shared_ptr<BPFMap> GetRulesMatchMap() const;
  std::shared_ptr<BPFMap> GetFramedRouteMappingMap() const;
  std::shared_ptr<BPFMap> GetFramedRoutingFlagMap() const;
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
   * Uses ConfigureMapMaxEntries(skel->maps.field, "name", size) -- the same
   * pattern as the original upf_xdp_user.cpp and all other program classes.
   * Called inside the open_fn lambda before the skeleton is returned.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_session_lookup_ip_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   *
   * Called from Setup() so that map pointers are valid before the program
   * is loaded into the kernel.
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_session_lookup_ip_kern_c* skeleton_ = nullptr;
  std::shared_ptr<SessionLookupIPLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Maps -- pipeline_maps.h
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> session_by_ue_ip_map_;
  std::shared_ptr<BPFMap> pdrs_per_session_map_;
  std::shared_ptr<BPFMap> session_qos_enabled_map_;
  std::shared_ptr<BPFMap> rules_match_pdr_map_;
  std::shared_ptr<BPFMap> framed_route_mapping_map_;
  std::shared_ptr<BPFMap> framed_routing_flag_map_;
  std::shared_ptr<BPFMap> feature_dispatch_map_;
  //----------------------------------------------------------------------------
  // Maps -- tail_call_dispatcher.h
  // Shared from the primary entry program via bpf_map__reuse_fd.
  // Primary is n3_ (IP PDU) or n3_eth_ (ETH PDU) -- both include
  // tail_call_dispatcher.h so the same maps exist in either case.
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMap> tail_call_progs_map_;
  std::shared_ptr<BPFMap> packet_ctx_map_;
  std::shared_ptr<BPFMap> session_rules_enabled_map_;
};

#endif /* SESSION_LOOKUP_IP_USER_H_ */
