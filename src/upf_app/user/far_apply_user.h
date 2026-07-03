/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FAR_APPLY_USER_H_
#define FAR_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <xdp_far_apply_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using FarProgramLifeCycle = ProgramLifeCycle<xdp_far_apply_kern_c>;

/**
 * @class FARProgram
 * @brief Manages the xdp_far_apply XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * SessionLookupIPProgram. Always instantiated by UPF_XDPProgram.
 *
 * Lifecycle (orchestrated by UPF_XDPProgram):
 *   1. Constructor  -- creates lifecycle_, does NOT open skeleton.
 *   2. UPF_XDPProgram calls GetLifeCycle()->open() before ShareMaps().
 *   3. UPF_XDPProgram::ShareMaps(primary, this) -- reuse_fd for shared maps.
 *   4. Setup()      -- InitializeMaps() + load() (no attach, no link).
 *   5. TearDown()   -- lifecycle_->tearDown().
 */
class FARProgram : public BPFProgram {
 public:
  /** @brief Constructor -- creates lifecycle_, does NOT open skeleton. */
  FARProgram();

  /** @brief Destructor. */
  virtual ~FARProgram();

  /**
   * @brief Initialize maps and load the XDP program into the kernel.
   *
   * Order: lifecycle_->open() (idempotent) -> InitializeMaps() -> load().
   * Must be called AFTER UPF_XDPProgram::ShareMaps().
   * No attach() or link() -- stage program, reached via tail call only.
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
  std::shared_ptr<FarProgramLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /** @brief Returns the raw bpf_object_skeleton pointer. */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns the xdp_program* for insertion into tail_call_progs_map.
   *
   * Called by UPF_XDPProgram::InsertProgramSlot(PROG_FAR_APPLY, ...).
   */
  struct bpf_program* GetXdpProgram() const;

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps() const;

  /** @name Direct map accessors (interfaces_maps.h + arp_maps.h -- owned) */
  ///@{
  std::shared_ptr<BPFMap> GetUpfInterfaceMap() const;
  std::shared_ptr<BPFMap> GetRedirectInterfacesMap() const;
  std::shared_ptr<BPFMap> GetArpTableMap() const;
  ///@}

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

 private:
  /**
   * @brief Configure max_entries for all runtime-sized maps.
   *
   * Sizes maps from interfaces_maps.h and arp_maps.h.
   * Pipeline and ETH maps are shared via reuse_fd -- not sized here.
   * Also sets all 7 rodata fields.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_far_apply_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   *
   * Only wraps the 3 maps owned by FARProgram. Pipeline and ETH maps
   * are accessed via UPF_XDPProgram::GetMapByName() delegation.
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_far_apply_kern_c* skeleton_ = nullptr;
  std::shared_ptr<FarProgramLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Maps
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  /* interfaces_maps.h -- owned, runtime-sized */
  std::shared_ptr<BPFMap> upf_interface_map_;
  std::shared_ptr<BPFMap> redirect_interfaces_map_;
  /* arp_maps.h -- owned, runtime-sized */
  std::shared_ptr<BPFMap> arp_table_map_;
};

#endif /* FAR_APPLY_USER_H_ */