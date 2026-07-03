/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef N3_ETH_ENTRY_USER_H_
#define N3_ETH_ENTRY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <xdp_n3_eth_entry_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using N3EthEntryLifeCycle = ProgramLifeCycle<xdp_n3_eth_entry_kern_c>;

/**
 * @class N3EthEntryProgram
 * @brief Manages the xdp_n3_eth_entry XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * N3EntryProgram. Instantiated by UPF_XDPProgram when Ethernet PDU sessions
 * are configured (pdu_type == Ethernet).
 * Acts as the PRIMARY program for the ETH PDU path: loaded first so its
 * map FDs are shared to all other programs via bpf_map__reuse_fd.
 * n3_ (N3EntryProgram) is NOT instantiated in ETH PDU mode.
 *
 * Lifecycle (called from UPF_XDPProgram):
 *   1. Constructor  -- open skeleton + ConfigureMaps()
 *   2. Setup()      -- InitializeMaps() + load() + attach() + link()
 *   3. TearDown()   -- lifecycle_->tearDown()
 */
class N3EthEntryProgram : public BPFProgram {
 public:
  /**
   * @brief Constructor -- opens skeleton and configures maps.
   * @param gtp_interface Name of the N3 (GTP-U) network interface.
   */
  explicit N3EthEntryProgram(const std::string& gtp_interface);

  /** @brief Destructor. */
  virtual ~N3EthEntryProgram();

  /**
   * @brief Load, attach, and link the XDP program to the N3 interface.
   *
   * Order: InitializeMaps() → load() → attach() → link().
   */
  void Setup();

  /**
   * @brief Detach and unload the XDP program.
   */
  void TearDown();

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps();

  /**
   * @brief Get a map by name.
   * @param map_name BPF map name string.
   * @return Shared pointer to the map, or nullptr.
   */
  std::shared_ptr<BPFMap> GetMapByName(const std::string& map_name);

  /** @name Direct map accessors */
  ///@{
  std::shared_ptr<BPFMap> GetTailCallProgsMap() const;
  std::shared_ptr<BPFMap> GetPacketContextMap() const;
  std::shared_ptr<BPFMap> GetSessionRulesEnabledMap() const;
  std::shared_ptr<BPFMap> GetMcStatsMap() const;
  ///@}

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

  /**
   * @brief Returns the lifecycle for external orchestration by UPF_XDPProgram.
   *
   * Used to call open()/load()/attach()/link() independently, and to
   * implement IsNativeXdp() / GetXdpModeString() in UPF_XDPProgram
   * without these methods living in individual entry program classes.
   * Resolves TODO 2 from n3_entry_user.cpp.
   */
  std::shared_ptr<N3EthEntryLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /** @brief Returns the raw bpf_object_skeleton pointer. */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns true if the interface runs in native XDP mode.
   * @note See TODO in n3_entry_user.cpp -- to be relocated to UPF_XDPProgram.
   */
  bool IsNativeXdp(const std::string& interface) const;

  /**
   * @brief Returns a human-readable XDP mode string ("Native" or "SKB").
   * @note See TODO in n3_entry_user.cpp -- to be relocated to UPF_XDPProgram.
   */
  std::string GetXdpModeString(const std::string& interface) const;

 private:
  /**
   * @brief No-op for N3EthEntryProgram -- all maps are fixed size.
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_n3_eth_entry_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_n3_eth_entry_kern_c* skeleton_ = nullptr;
  std::shared_ptr<N3EthEntryLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Interface
  //----------------------------------------------------------------------------
  std::string gtp_interface_;

  //----------------------------------------------------------------------------
  // Maps (tail_call_dispatcher.h + stats_maps.h)
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> tail_call_progs_map_;
  std::shared_ptr<BPFMap> packet_ctx_map_;
  std::shared_ptr<BPFMap> session_rules_enabled_map_;
  std::shared_ptr<BPFMap> mc_stats_map_;
};

#endif /* N3_ETH_ENTRY_USER_H_ */
