/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef N6_ETH_ENTRY_USER_H_
#define N6_ETH_ENTRY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <xdp_n6_eth_entry_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "interfaces_types.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using N6EthEntryLifeCycle = ProgramLifeCycle<xdp_n6_eth_entry_kern_c>;

/**
 * @class N6EthEntryProgram
 * @brief Manages the xdp_n6_eth_entry XDP program lifecycle.
 *
 * Unlike the other three entry programs, this class performs real runtime
 * map sizing (interfaces_maps.h + eth_pdu_maps.h) and populates the
 * interface maps after load.
 * Secondary entry program on the ETH PDU path (n3_eth_ is primary).
 * Not instantiated in IP PDU mode.
 *
 * Lifecycle (called from UPF_XDPProgram):
 *   1. Constructor  -- open skeleton + ConfigureMaps() (runtime sizing)
 *   2. Setup()      -- InitializeMaps() + load() + attach() +
 *                      populate redirect/iface maps + link()
 *   3. TearDown()   -- lifecycle_->tearDown()
 */
class N6EthEntryProgram : public BPFProgram {
 public:
  /**
   * @brief Constructor -- opens skeleton and configures maps.
   * @param non_gtp_interface Name of the N6 network interface.
   */
  explicit N6EthEntryProgram(const std::string& non_gtp_interface);

  /** @brief Destructor. */
  virtual ~N6EthEntryProgram();

  /**
   * @brief Load, attach, populate interface maps, and link the XDP program.
   *
   * Order: InitializeMaps() → load() → attach() →
   *        populate redirect_interfaces_map → populate upf_interface_map →
   *        link().
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
  std::shared_ptr<BPFMap> GetRedirectInterfacesMap() const;
  std::shared_ptr<BPFMap> GetSessionByMacMap() const;
  std::shared_ptr<BPFMap> GetEthSessionMappingMap() const;
  std::shared_ptr<BPFMap> GetEthSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetEthRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> GetEthEgressIfindexMap() const;
  std::shared_ptr<BPFMap> GetMacPduSessionMap() const;
  std::shared_ptr<BPFMap> GetMcStatsMap() const;
  ///@}

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

  /**
   * @brief Returns the lifecycle for external orchestration by UPF_XDPProgram.
   * Resolves TODO 2 from n3_entry_user.cpp.
   */
  std::shared_ptr<N6EthEntryLifeCycle> GetLifeCycle() const {
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
   * @brief Set max_entries for all runtime-sized maps.
   *
   * Sizes maps from interfaces_maps.h and eth_pdu_maps.h.
   * Also sets rodata->MAX_UPF_INTERFACES.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_n6_eth_entry_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_n6_eth_entry_kern_c* skeleton_ = nullptr;
  std::shared_ptr<N6EthEntryLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Interface
  //----------------------------------------------------------------------------
  std::string non_gtp_interface_;

  //----------------------------------------------------------------------------
  // Maps
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  /* interfaces_maps.h */
  std::shared_ptr<BPFMap> upf_interface_map_;
  std::shared_ptr<BPFMap> redirect_interfaces_map_;
  /* eth_pdu_maps.h */
  std::shared_ptr<BPFMap> session_by_mac_map_;
  std::shared_ptr<BPFMap> eth_session_mapping_map_;
  std::shared_ptr<BPFMap> eth_session_pdrs_map_;
  std::shared_ptr<BPFMap> eth_rules_match_pdr_map_;
  std::shared_ptr<BPFMap> eth_egress_ifindex_map_;
  std::shared_ptr<BPFMap> mac_pdu_session_map_;
  /* stats_maps.h */
  std::shared_ptr<BPFMap> mc_stats_map_;
};

#endif /* N6_ETH_ENTRY_USER_H_ */
