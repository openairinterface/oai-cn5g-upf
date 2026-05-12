/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef URR_APPLY_USER_H_
#define URR_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <xdp_urr_apply_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"
#include <pfcp_urr.h>
#include <urr_types.h> /* struct urr_config, URR_TRIGGER_* */
#include <pfcp_session.hpp>

class BPFMaps;
class BPFMap;

using UrrProgramLifeCycle = ProgramLifeCycle<xdp_urr_apply_kern_c>;

/**
 * @struct urr_map_key
 * @brief Compound BPF map key: {seid, urr_id}.
 */
struct urr_map_key {
  uint64_t seid;
  uint32_t urr_id;
  uint32_t _pad;
} __attribute__((packed));

/**
 * @struct urr_volume_t
 * @brief Per-URR volume counters maintained atomically by the data plane.
 */
struct urr_volume_t {
  uint64_t ul_octets;
  uint64_t dl_octets;
  uint64_t ul_packets;
  uint64_t dl_packets;
};

/**
 * @class URRProgram
 * @brief Manages the xdp_urr_apply XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * SessionLookupIPProgram. Instantiated by UPF_XDPProgram only when
 * flags.enable_urr is set.
 *
 * Lifecycle (orchestrated by UPF_XDPProgram):
 *   1. Constructor  -- creates lifecycle_, does NOT open skeleton.
 *   2. UPF_XDPProgram calls GetLifeCycle()->open() before ShareMaps().
 *   3. UPF_XDPProgram::ShareMaps(primary, this) -- reuse_fd for shared maps.
 *   4. Setup()      -- InitializeMaps() + load() (no attach, no link).
 *   5. TearDown()   -- lifecycle_->tearDown().
 */
class URRProgram : public BPFProgram {
 public:
  /** @brief Constructor -- creates lifecycle_, does NOT open skeleton. */
  URRProgram();

  /** @brief Destructor. */
  virtual ~URRProgram() = default;

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
   * @note Distinct from TearDown(seid, urrs) which removes session map entries.
   */
  void TearDown();

  /**
   * @brief Returns the lifecycle for external orchestration.
   *
   * UPF_XDPProgram uses this to call open() before ShareMaps().
   */
  std::shared_ptr<UrrProgramLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /** @brief Returns the raw bpf_object_skeleton pointer. */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns the xdp_program* for insertion into tail_call_progs_map.
   *
   * Called by UPF_XDPProgram::InsertProgramSlot(PROG_URR_APPLY, ...).
   */
  struct bpf_program* GetXdpProgram() const;

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps() const;

  /** @name Direct map accessors (urr_maps.h) */
  ///@{
  std::shared_ptr<BPFMap> GetUrrConfigMap() const;
  std::shared_ptr<BPFMap> GetUrrVolumeMap() const;
  std::shared_ptr<BPFMap> GetUrrReportRingbuf() const;
  ///@}

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

  // ==========================================================================
  // Session lifecycle (called by SessionProgramManager)
  // ==========================================================================

  /**
   * @brief Configure all URRs for a new session.
   *
   * Populates urr_config_map and initialises urr_volume_counters_map for
   * each URR. Volume counters are inserted with BPF_NOEXIST so they start
   * at zero without overwriting any existing data.
   *
   * @param seid  PFCP session identifier.
   * @param urrs  URR IEs from PFCP Session Establishment Request.
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_urr>>& urrs);

  /**
   * @brief Update a single URR for an existing session.
   *
   * Overwrites the config entry (BPF_EXIST) without touching the
   * volume counters in urr_volume_counters_map.
   *
   * @param seid  PFCP session identifier.
   * @param urr   Updated URR IE from PFCP Session Modification Request.
   */
  void Update(uint64_t seid, const std::shared_ptr<pfcp::pfcp_urr>& urr);

  /**
   * @brief Remove a single URR from all maps.
   * @param seid    PFCP session identifier.
   * @param urr_id  URR identifier to remove.
   */
  void Remove(uint64_t seid, uint32_t urr_id);

  /**
   * @brief Tear down all URRs for a session on deletion.
   *
   * Does NOT send usage reports -- caller is responsible for collecting
   * final usage before calling TearDown().
   *
   * @param seid  PFCP session identifier.
   * @param urrs  URRs to remove.
   */
  void TearDown(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_urr>>& urrs);

  /**
   * @brief Populate urr_config_map for a single URR.
   * @param seid   PFCP session identifier.
   * @param urr    URR IE to convert and write.
   * @param flags  BPF_ANY / BPF_NOEXIST / BPF_EXIST.
   */
  void PopulateUrrConfigMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_urr>& urr,
      uint64_t flags = BPF_ANY);

  /**
   * @brief Initialise urr_volume_counters_map entry (BPF_NOEXIST).
   *
   * Creates a zero-initialised counter entry only if it does not already
   * exist, preserving any in-flight accounting across session updates.
   *
   * @param seid    PFCP session identifier.
   * @param urr_id  URR identifier.
   */
  void InitUrrVolumeMap(uint64_t seid, uint32_t urr_id);

  /**
   * @brief Read current volume counters for a URR.
   * @param seid    PFCP session identifier.
   * @param urr_id  URR identifier.
   * @param[out] volume  Output volume counter struct.
   * @return true if entry found and populated.
   */
  bool ReadVolumeCounters(
      uint64_t seid, uint32_t urr_id, urr_volume_t& volume) const;

 private:
  /**
   * @brief Configure max_entries for all runtime-sized maps.
   *
   * Uses ConfigureMapMaxEntries(skel->maps.field, "name", size).
   * Called inside the open_fn lambda before the skeleton is returned.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_urr_apply_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   */
  void InitializeMaps();

  /** @brief Build a urr_map_key from SEID and URR_ID (pad zeroed). */
  static urr_map_key MakeKey(uint64_t seid, uint32_t urr_id);

  /** @brief Translate PFCP URR IE into BPF pfcp_urr struct. */
  static void ConvertUrr(
      const pfcp::pfcp_urr& pfcp_ie, struct pfcp_urr& bpf_urr);

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_urr_apply_kern_c* skeleton_ = nullptr;
  std::shared_ptr<UrrProgramLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Maps (urr_maps.h)
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> urr_volume_counters_map_;
  std::shared_ptr<BPFMap> urr_config_map_;
  std::shared_ptr<BPFMap> urr_report_ringbuf_map_;
};

#endif /* URR_APPLY_USER_H_ */
