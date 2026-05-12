/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef QER_APPLY_USER_H_
#define QER_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <xdp_qer_apply_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using QerProgramLifeCycle = ProgramLifeCycle<xdp_qer_apply_kern_c>;

/**
 * @class QERProgram
 * @brief Manages the xdp_qer_apply XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * URRProgram, BARProgram, and MARProgram. Instantiated by UPF_XDPProgram
 * only when flags.enable_qer is set.
 *
 * Lifecycle (orchestrated by UPF_XDPProgram):
 *   1. Constructor  -- creates lifecycle_, does NOT open skeleton.
 *   2. UPF_XDPProgram calls GetLifeCycle()->open() before ShareMaps().
 *   3. UPF_XDPProgram::ShareMaps(primary, this) -- reuse_fd for all maps.
 *   4. Setup()      -- InitializeMaps() + load() (no attach, no link).
 *   5. TearDown()   -- lifecycle_->tearDown().
 */
class QERProgram : public BPFProgram {
 public:
  /** @brief Constructor -- creates lifecycle_, does NOT open skeleton. */
  QERProgram();

  /** @brief Destructor. */
  virtual ~QERProgram() = default;

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
  std::shared_ptr<QerProgramLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /** @brief Returns the raw bpf_object_skeleton pointer. */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns the xdp_program* for insertion into tail_call_progs_map.
   *
   * Called by UPF_XDPProgram::InsertProgramSlot(PROG_QER_APPLY, ...).
   */
  struct bpf_program* GetXdpProgram() const;

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps() const;

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

 private:
  /**
   * @brief Set rodata constants before skeleton load.
   *
   * xdp_qer_apply_kern.c includes pipeline_maps.h which declares 7 rodata
   * fields. No ConfigureMapMaxEntries() calls are needed because this
   * program owns no maps -- all maps are shared from the primary via
   * bpf_map__reuse_fd before Setup() is called.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_qer_apply_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMaps after open.
   *
   * All maps are shared from the primary entry program via reuse_fd.
   * maps_ is created here solely to support GetMapCount().
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_qer_apply_kern_c* skeleton_ = nullptr;
  std::shared_ptr<QerProgramLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Maps -- NONE owned by this program.
  // maps_ wraps the skeleton for GetMapCount() only.
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
};

#endif /* QER_APPLY_USER_H_ */