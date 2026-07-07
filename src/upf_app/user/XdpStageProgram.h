/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef XDP_STAGE_PROGRAM_H_
#define XDP_STAGE_PROGRAM_H_

#include <ProgramLifeCycle.hpp>
#include <BPFProgram.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include <bpf/libbpf.h>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include "logger.hpp"

// ==========================================================================
// XDPStageProgram<SkelType>
// ==========================================================================

template<typename SkelType>
class XDPStageProgram : public BPFProgram {
 public:
  // ==========================================================================
  // Lifecycle -- common across all stage programs
  // ==========================================================================

  /**
   * @brief Load skeleton and wrap all map FDs.
   * Call after UPF_XDPProgram::ShareMaps() has reused infrastructure FDs.
   */
  virtual void Load() {
    lifecycle_->load();
    InitMaps();
  }

  /**
   * @brief Attach skeleton programs (rarely needed for tail-call stages).
   */
  void Attach() { lifecycle_->attach(); }

  // ==========================================================================
  // BPF object access
  // ==========================================================================

  /**
   * @brief Return the underlying BPF object for map FD sharing.
   * Used by UPF_XDPProgram::ShareMaps(src, this->GetBpfObject()).
   */
  struct bpf_object* GetBpfObject() const {
    return skeleton_ ? skeleton_->obj : nullptr;
  }

  // ==========================================================================
  // Map access -- generic, no per-map getters needed in base
  // ==========================================================================

  /**
   * @brief Return all maps container (from this skeleton).
   */
  std::shared_ptr<BPFMaps> GetMaps() const { return maps_; }

  /**
   * @brief Get a BPFMap wrapper by map name.
   *
   * Replaces all individual GetXxxMap() boilerplate.
   * Subclasses provide thin typed wrappers:
   *   std::shared_ptr<BPFMap> GetUrrConfigMap() const {
   *     return GetMap("urr_config_map");
   *   }
   *
   * @param name  BPF map name as declared in the kernel program.
   * @return nullptr if maps_ not initialised or map not found.
   */
  std::shared_ptr<BPFMap> GetMap(const std::string& name) const {
    if (!maps_) return nullptr;
    return std::make_shared<BPFMap>(maps_->GetMap(name.c_str()));
  }

 protected:
  // ==========================================================================
  // Called by subclass constructor
  // ==========================================================================

  /**
   * @brief Open the skeleton, store lifecycle and skeleton pointer.
   *
   * The open_fn lambda should:
   *   1. Call SkelType__open().
   *   2. Call ConfigureMapSize() for each map that needs sizing.
   *   3. Return the skeleton pointer.
   *
   * skeleton_ is set BEFORE open_fn returns so ConfigureMapSize() can
   * use it via skeleton_->obj.
   *
   * @throws std::runtime_error if open_fn returns nullptr.
   */
  void InitLifecycle(
      std::function<SkelType*()> open_fn, int (*load_fn)(SkelType*),
      int (*attach_fn)(SkelType*), void (*destroy_fn)(SkelType*)) {
    /*
     * Wrap the user's open_fn to capture skeleton_ before returning,
     * so ConfigureMapSize() (called inside open_fn) can use skeleton_->obj.
     */
    auto wrapped_open = [this, open_fn]() -> SkelType* {
      SkelType* s = open_fn();
      if (!s)
        throw std::runtime_error(
            "XDPStageProgram: skeleton open returned null");
      skeleton_ = s;
      return s;
    };

    lifecycle_ = std::make_shared<ProgramLifeCycle<SkelType>>(
        wrapped_open, load_fn, attach_fn, destroy_fn);
    lifecycle_->open(); /* calls wrapped_open -- sets skeleton_ */
  }

  // ==========================================================================
  // Map configuration helper -- pre-load, called inside open_fn
  // ==========================================================================

  /**
   * @brief Set max_entries for a map by name (before load).
   *
   * Uses bpf_object__find_map_by_name which is generic across all skeleton
   * types (skeleton_->obj is always struct bpf_object*). Safe to call from
   * inside the open_fn lambda since skeleton_ is set before open_fn returns.
   *
   * @param name        BPF map name as declared in the kernel program.
   * @param max_entries Maximum number of entries.
   */
  void ConfigureMapSize(const char* name, uint32_t max_entries) {
    if (!skeleton_) return;
    struct bpf_map* m = bpf_object__find_map_by_name(skeleton_->obj, name);
    if (!m) {
      Logger::upf_app().warn(
          "ConfigureMapSize: map '%s' not found in skeleton", name);
      return;
    }
    if (bpf_map__set_max_entries(m, max_entries) != 0)
      Logger::upf_app().warn(
          "ConfigureMapSize: set_max_entries failed for '%s'", name);
  }

  // ==========================================================================
  // Map initialisation -- post-load, called inside Load()
  // ==========================================================================

  /**
   * @brief Wrap all map FDs in a BPFMaps container.
   *
   * Called automatically by Load() after lifecycle_->load().
   * skeleton_->skeleton is the bpf_object_skeleton* used by BPFMaps --
   * this member is always present in libbpf skeletons.
   */
  void InitMaps() {
    if (!skeleton_) return;
    maps_ = std::make_shared<BPFMaps>(skeleton_->skeleton);
  }

  // ==========================================================================
  // Protected members -- accessible to subclass
  // ==========================================================================

  SkelType* skeleton_ = nullptr;
  std::shared_ptr<ProgramLifeCycle<SkelType>> lifecycle_;
  std::shared_ptr<BPFMaps> maps_;
};

#endif /* XDP_STAGE_PROGRAM_H_ */