/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef UPF_XDP_USER_H_
#define UPF_XDP_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <initializer_list>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include <BPFProgram.h>
#include "upf_pipeline_config.h"
#include "upf_network_config.h"
#include "interfaces_types.h"
#include "framed_routing_bpf.h"

/* Entry program class headers */
#include "n3_entry_user.h"
#include "n6_entry_user.h"
#include "n3_eth_entry_user.h"
#include "n6_eth_entry_user.h"

/* Pipeline stage program headers */
#include "session_lookup_ip_user.h"
#include "session_lookup_eth_user.h"
#include "pdr_match_user.h"
#include "far_apply_user.h"
#include "qer_apply_user.h"
#include "qer_tc_user.h"
#include "urr_apply_user.h"
#include "bar_apply_user.h"
#include "mar_apply_user.h"
#include "startup_banner.hpp"

class BPFMaps;
class BPFMap;

// ==========================================================================
// UPF_XDPProgram
// ==========================================================================

class UPF_XDPProgram : public BPFProgram {
 public:
  // ==========================================================================
  // Constructor / Destructor
  // ==========================================================================

  /**
   * @brief Constructor -- stores interface names only.
   *
   * No programs are instantiated here. All instantiation happens in Setup()
   * once PipelineFeatureFlags are available.
   *
   * @param gtp_interface     Name of the N3 (GTP-U) network interface.
   * @param non_gtp_interface Name of the N6 network interface.
   */
  explicit UPF_XDPProgram(
      const std::string& gtp_interface, const std::string& non_gtp_interface);

  /** @brief Destructor -- calls TearDown(). */
  virtual ~UPF_XDPProgram();

  // ==========================================================================
  // Lifecycle
  // ==========================================================================

  /**
   * @brief Instantiate, load, share maps, attach, and link all programs.
   *
   * PDU type controls which entry programs are instantiated and linked:
   *   IP  -> n3_ (primary) + n6_.
   *   ETH -> n3_eth_ (primary) + n6_eth_.
   *
   * Feature flags control which optional stage programs are instantiated:
   *     enable_qer -> qer_
   *     enable_urr -> urr_
   *     enable_bar -> bar_
   *     enable_mar -> mar_
   *
   * Load order:
   *   1. Instantiate entry programs based on pdu_type.
   *   2. Instantiate stage programs based on pdu_type and feature flags.
   *   3. Open all programs (ConfigureMaps runs, no kernel load yet).
   *   4. Load the primary entry program -- creates shared map FDs.
   *   5. ShareMaps(primary, all_others) via bpf_map__reuse_fd.
   *   6. Load all remaining programs.
   *   7. Wrap primary's 4 infrastructure maps in BPFMap objects.
   *   8. Attach and link the pdu_type-matched entry programs to interfaces.
   *   9. Populate tail_call_progs_map based on feature flags.
   *
   * @param flags  Pipeline feature configuration (PDU type, enabled rules).
   */
  void Setup(const PipelineFeatureFlags& flags);

  /** @brief Detach all programs and release all resources. */
  void TearDown();

  /** @brief Remove a slot from the tail_call_progs_map. */
  void RemoveProgramMap(uint32_t key);

  // ==========================================================================
  // Map access
  // ==========================================================================

  /** @brief Returns the container of the primary entry skeleton's maps. */
  std::shared_ptr<BPFMaps> GetMaps();

  /**
   * @brief Get any pipeline map by name.
   *
   * Searches infrastructure maps first, then delegates to stage programs.
   * Preserved for SessionProgramManager compatibility.
   */
  std::shared_ptr<BPFMap> GetMapByName(const std::string& map_name);

  // ==========================================================================
  // Interface configuration
  // ==========================================================================

  /** @brief Populate one entry in upf_interface_map (IP PDU path only). */
  void CreateUpfInterfaceMapEntry(reference_point_t reference_point);

  // ==========================================================================
  // Framed routing
  // ==========================================================================

  std::shared_ptr<BPFMap> GetFramedRouteMappingMap();
  void UpdateFramedRouteMappingMap(uint32_t ue_ip, FramedRoutingKeyBPF key);
  void RemoveFramedRoute(FramedRoutingKeyBPF key);
  void SetFramedRouting(bool enable);

  // ==========================================================================
  // Direct map getters -- primary entry skeleton infrastructure maps
  // ==========================================================================

  /** @brief tail_call_progs_map from the primary entry skeleton. */
  std::shared_ptr<BPFMap> GetTailCallProgsMap() const {
    return tail_call_progs_map_;
  }

  /** @brief packet_context_map from the primary entry skeleton. */
  std::shared_ptr<BPFMap> GetPacketContextMap() const {
    return packet_ctx_map_;
  }

  /** @brief session_rules_enabled_map from the primary entry skeleton. */
  std::shared_ptr<BPFMap> GetSessionRulesMap() const {
    return session_rules_map_;
  }

  /** @brief mc_stats_map from the primary entry skeleton. */
  std::shared_ptr<BPFMap> GetMcStatsMap() const { return mc_stats_map_; }

  // ==========================================================================
  // Direct map getters -- delegated to stage programs
  // ==========================================================================

  std::shared_ptr<BPFMap> GetSessionMappingMap() const;
  std::shared_ptr<BPFMap> GetSessionMacMap() const;
  std::shared_ptr<BPFMap> GetRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> GetSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetSdfFilterMap() const;
  std::shared_ptr<BPFMap> GetQosEnablingMap() const;
  std::shared_ptr<BPFMap> GetFeatureDispatchMap() const;

  // ==========================================================================
  // Pipeline program accessors
  // ==========================================================================

  /**
   * @note Exactly one of (n3_, n3_eth_) and one of (n6_, n6_eth_) is
   *       non-null after Setup(). The null ones were never instantiated.
   */
  std::shared_ptr<N3EntryProgram> GetN3EntryProgram() const { return n3_; }
  std::shared_ptr<N6EntryProgram> GetN6EntryProgram() const { return n6_; }
  std::shared_ptr<N3EthEntryProgram> GetN3EthEntryProgram() const {
    return n3_eth_;
  }
  std::shared_ptr<N6EthEntryProgram> GetN6EthEntryProgram() const {
    return n6_eth_;
  }
  std::shared_ptr<SessionLookupIPProgram> GetSessionLookupIPProgram() const {
    return sl_ip_;
  }
  std::shared_ptr<SessionLookupETHProgram> GetSessionLookupETHProgram() const {
    return sl_eth_;
  }
  std::shared_ptr<PdrMatchProgram> GetPdrMatchProgram() const { return pdr_; }
  std::shared_ptr<FARProgram> GetFarProgram() const { return far_; }
  /** @brief Returns the XDP gate-check QER program (PROG_QER_APPLY slot). */
  std::shared_ptr<QERProgram> GetQerProgram() const { return qer_; }

  /** @brief Returns the TC-BPF QER shaping program (per-session). */
  std::shared_ptr<QERTCProgram> GetQerTcProgram() const { return qer_tc_; }
  std::shared_ptr<URRProgram> GetUrrProgram() const { return urr_; }
  std::shared_ptr<BARProgram> GetBarProgram() const { return bar_; }
  std::shared_ptr<MARProgram> GetMarProgram() const { return mar_; }

  // ==========================================================================
  // Status
  // ==========================================================================

  /**
   * @brief Sum of GetMapCount() over all instantiated program instances.
   *
   * Resolves TODO 1 from n3_entry_user.cpp. Only non-null programs
   * contribute -- the uninstantiated pair (IP vs ETH) is excluded.
   */
  size_t GetTotalMapCount() const;

  /**
   * @brief Compatibility alias for GetTotalMapCount().
   *
   * Preserved for callers (e.g. UserPlaneComponent) that predate the
   * per-program split and still call GetMapCount() on UPF_XDPProgram.
   */
  size_t GetMapCount() const { return GetTotalMapCount(); }

  /**
   * @brief Returns true if @p iface runs in native XDP mode.
   *
   * Resolves TODO 2 from n3_entry_user.cpp.
   * Delegates to GetLifeCycle() on the entry program attached to @p iface.
   *
   * @param iface  Interface name (gtp_interface_ or non_gtp_interface_).
   */
  bool IsNativeXdp(const std::string& iface) const;

  /**
   * @brief Returns "Native (Hardware)" or "SKB (Software)" for @p iface.
   *
   * Resolves TODO 2 from n3_entry_user.cpp.
   * Delegates to GetLifeCycle() on the entry program attached to @p iface.
   */
  std::string GetXdpModeString(const std::string& iface) const;

  /** @brief Build ordered program load info for DisplayPipelineLoadTree(). */
  std::vector<ProgramLoadInfo> BuildPipelineLoadInfo(
      const PipelineFeatureFlags& flags) const;

 private:
  // ==========================================================================
  // Internal helpers
  // ==========================================================================

  /**
   * @brief Share all map FDs from @p src_obj to @p dst_obj by name.
   *
   * For each map in @p dst_obj whose name also exists in @p src_obj,
   * calls bpf_map__reuse_fd so both objects use the same kernel map.
   * Must be called after the primary program is loaded and before others.
   */
  void ShareMapsOwned(
      struct bpf_object* src, struct bpf_object* dst,
      const std::initializer_list<const char*>& owned_maps);
  void ShareMaps(struct bpf_object* src_obj, struct bpf_object* dst_obj);

  /**
   * @brief Wrap the primary skeleton's 4 tail_call maps in BPFMap objects.
   *
   * @param primary_skeleton  bpf_object_skeleton* from the primary entry
   * program.
   */
  void InitializeMaps(struct bpf_object_skeleton* primary_skeleton);

  /** @brief Insert a BPF program FD into tail_call_progs_map at @p index. */
  bool InsertProgramSlot(uint32_t index, struct bpf_program* prog);

  /** @brief Populate tail_call_progs_map based on feature flags. */
  void PopulateProgramArray(const PipelineFeatureFlags& flags);

  // ==========================================================================
  // Entry program instances -- exactly ONE pair non-null after Setup()
  // ==========================================================================

  std::shared_ptr<N3EntryProgram> n3_;  ///< IP PDU primary  (null in ETH mode)
  std::shared_ptr<N6EntryProgram> n6_;  ///< IP PDU          (null in ETH mode)
  std::shared_ptr<N3EthEntryProgram>
      n3_eth_;  ///< ETH PDU primary (null in IP  mode)
  std::shared_ptr<N6EthEntryProgram>
      n6_eth_;  ///< ETH PDU         (null in IP  mode)

  // ==========================================================================
  // Stage program instances
  // ==========================================================================

  std::shared_ptr<SessionLookupIPProgram>
      sl_ip_;  ///< IP PDU path  (null in ETH mode)
  std::shared_ptr<SessionLookupETHProgram>
      sl_eth_;                            ///< ETH PDU path (null in IP  mode)
  std::shared_ptr<PdrMatchProgram> pdr_;  ///< always
  std::shared_ptr<FARProgram> far_;       ///< always
  /** XDP gate-check program -- tail-called at PROG_QER_APPLY slot. */
  std::shared_ptr<QERProgram> qer_;  ///< null unless flags.enable_qer
  /** TC-BPF shaping program -- HTB + redirect, attached per-session. */
  std::shared_ptr<QERTCProgram> qer_tc_;  ///< null unless flags.enable_qer
  std::shared_ptr<URRProgram> urr_;       ///< null unless flags.enable_urr
  std::shared_ptr<BARProgram> bar_;       ///< null unless flags.enable_bar
  std::shared_ptr<MARProgram> mar_;       ///< null unless flags.enable_mar

  // ==========================================================================
  // Interface names and feature flags
  // ==========================================================================

  std::string gtp_interface_;
  std::string non_gtp_interface_;
  PipelineFeatureFlags features_;

  // ==========================================================================
  // Infrastructure maps -- from the primary entry skeleton.
  // Both xdp_n3_entry_kern.c and xdp_n3_eth_entry_kern.c include
  // tail_call_dispatcher.h + stats_maps.h, so the same 4 maps exist
  // regardless of which program is primary.
  // ==========================================================================

  std::shared_ptr<BPFMaps> maps_;

  std::shared_ptr<BPFMap> tail_call_progs_map_;  ///< tail_call_progs_map
  std::shared_ptr<BPFMap> packet_ctx_map_;       ///< packet_context_map
  std::shared_ptr<BPFMap> session_rules_map_;    ///< session_rules_enabled_map
  std::shared_ptr<BPFMap> mc_stats_map_;         ///< mc_stats_map
  /** upf_interface_map: from FAR (IP PDU) or n6_eth_ (ETH PDU). */
  std::shared_ptr<BPFMap> upf_iface_map_;
};

#endif /* UPF_XDP_USER_H_ */
