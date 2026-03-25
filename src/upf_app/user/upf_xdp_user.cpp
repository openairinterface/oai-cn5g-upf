/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */
// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Rewritten to match split-skeleton upf_xdp_user.h.
 *              Members: skel_n3_, skel_n6_, skel_n3_eth_, skel_n6_eth_.
 *              Only 7 infrastructure maps stored directly; all others
 *              delegated to stage programs via GetMap() calls.
 *              ConfigureEntryMaps() replaces ConfigurePfcpSessionLookupMaps().
 *              ShareMaps() replaces ShareMapsFromPrimary().
 *              All upf_cfg removed -- sizing via upf:: getters only.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol
 *              3GPP TS 23.501          -- 5G System Architecture
 */
// clang-format on

#include "upf_xdp_user.h"
#include "tail_call_types.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_xdp_limits.h"
#include "UserPlaneComponent.h"
#include "interfaces_types.h"

/* Section: Constructor / Destructor */

//------------------------------------------------------------------------------
UPF_XDPProgram::UPF_XDPProgram(
    const std::string& gtp_interface, const std::string& non_gtp_interface)
    : BPFProgram(),
      gtp_interface_(gtp_interface),
      non_gtp_interface_(non_gtp_interface) {
  Logger::upf_app().info(
      "UPF_XDPProgram: created (N3=%s N6=%s)", gtp_interface_.c_str(),
      non_gtp_interface_.c_str());
}

//------------------------------------------------------------------------------
UPF_XDPProgram::~UPF_XDPProgram() {
  TearDown();
}

/* Section: Entry map configuration */

//------------------------------------------------------------------------------
void UPF_XDPProgram::ConfigureEntryMaps(struct xdp_n3_entry_kern_c* skel) {
  /*
   * Configure max_entries for the 4 configurable maps in xdp_n3_entry_kern.c.
   * Confirmed from skeleton: no rodata section in xdp_n3_entry_kern_c.
   */
  if (!skel) throw std::runtime_error("ConfigureEntryMaps: null skeleton");

  auto set_size = [&](const char* name, uint32_t sz) {
    struct bpf_map* m = bpf_object__find_map_by_name(skel->obj, name);
    if (m)
      bpf_map__set_max_entries(m, sz);
    else
      Logger::upf_app().warn("ConfigureEntryMaps: map '%s' not found", name);
  };

  set_size("upf_interface_map", upf::GetMaxUpfInterfaces());
  set_size("redirect_interfaces_map", upf::GetMaxUpfRedirectInterfaces());
  set_size("arp_table_map", upf::GetMaxArpEntries());
  set_size("session_rules_enabled_map", upf::GetMaxPduSessions());

  Logger::upf_app().debug(
      "ConfigureEntryMaps: ifaces=%u redirect=%u arp=%u sessions=%u",
      upf::GetMaxUpfInterfaces(), upf::GetMaxUpfRedirectInterfaces(),
      upf::GetMaxArpEntries(), upf::GetMaxPduSessions());
}

/* Section: Map sharing */

//------------------------------------------------------------------------------
void UPF_XDPProgram::ShareMaps(
    struct bpf_object* src_obj, struct bpf_object* dst_obj) {
  if (!src_obj || !dst_obj) return;
  struct bpf_map* dst_map;
  bpf_object__for_each_map(dst_map, dst_obj) {
    const char* name    = bpf_map__name(dst_map);
    struct bpf_map* src = bpf_object__find_map_by_name(src_obj, name);
    if (!src) continue;
    int fd = bpf_map__fd(src);
    if (fd < 0) continue;
    if (bpf_map__reuse_fd(dst_map, fd) != 0)
      Logger::upf_app().warn("ShareMaps: reuse_fd failed for '%s'", name);
  }
}

/* Section: Setup
 *
 * ARCHITECTURE
 * ============
 * Entry programs have dedicated classes (N3EntryProgram, N6EntryProgram,
 * N3EthEntryProgram, N6EthEntryProgram) each owning a ProgramLifeCycle<T>.
 *
 * N3EntryProgram is always PRIMARY -- it is the only entry skeleton that
 * has upf_interface_map, redirect_interfaces_map, arp_table_map.
 * These infrastructure maps are needed by all pipeline stages.
 * N3EntryProgram is always loaded first so its map FDs are valid.
 * In ETH PDU mode N3EntryProgram is still loaded (for map FDs) but
 * only N3EthEntryProgram and N6EthEntryProgram are linked to interfaces.
 *
 * Attachment uses lifecycle_->link(prog_name, interface) -- matching the
 * original monolithic pattern. NOT __attach(), NOT bpf_xdp_attach().
 * TearDown() is handled automatically by lifecycle_ destructors.
 */

//------------------------------------------------------------------------------
void UPF_XDPProgram::Setup(const PipelineFeatureFlags& flags) {
  features_ = flags;

  /* Step 1: Open n3_entry (PRIMARY) and configure its infrastructure maps */
  skel_n3_ = xdp_n3_entry_kern_c__open();
  if (!skel_n3_)
    throw std::runtime_error("Failed to open xdp_n3_entry skeleton");
  ConfigureEntryMaps(skel_n3_);

  /* Step 2: Open remaining entry skeletons */
  skel_n6_     = xdp_n6_entry_kern_c__open();
  skel_n3_eth_ = xdp_n3_eth_entry_kern_c__open();
  skel_n6_eth_ = xdp_n6_eth_entry_kern_c__open();
  if (!skel_n6_ || !skel_n3_eth_ || !skel_n6_eth_)
    throw std::runtime_error("Failed to open secondary entry skeletons");

  /* Step 3: Instantiate stage programs (constructors open + size their maps) */
  sl_ip_  = std::make_shared<SessionLookupIPProgram>();
  sl_eth_ = std::make_shared<SessionLookupETHProgram>();
  pdr_    = std::make_shared<PdrMatchProgram>();
  far_    = std::make_shared<FARProgram>();
  qer_    = std::make_shared<QERProgram>();
  urr_    = std::make_shared<URRProgram>();
  bar_    = std::make_shared<BARProgram>();
  mar_    = std::make_shared<MARProgram>();

  /* Step 4: Load n3_entry first -- creates infrastructure map FDs */
  if (xdp_n3_entry_kern_c__load(skel_n3_) != 0)
    throw std::runtime_error("Failed to load xdp_n3_entry");
  Logger::upf_app().info("UPF_XDPProgram: n3_entry loaded (primary)");

  /* Step 5: Share n3_entry infrastructure maps to all other objects */
  struct bpf_object* n3_obj = skel_n3_->obj;
  ShareMaps(n3_obj, skel_n6_->obj);
  ShareMaps(n3_obj, skel_n3_eth_->obj);
  ShareMaps(n3_obj, skel_n6_eth_->obj);
  ShareMaps(n3_obj, sl_ip_->GetBpfObject());
  ShareMaps(n3_obj, sl_eth_->GetBpfObject());
  ShareMaps(n3_obj, pdr_->GetBpfObject());
  ShareMaps(n3_obj, far_->GetBpfObject());
  ShareMaps(n3_obj, urr_->GetBpfObject());
  ShareMaps(n3_obj, bar_->GetBpfObject());
  ShareMaps(n3_obj, mar_->GetBpfObject());

  /* Step 6: Load stage programs */
  sl_ip_->Load();
  sl_eth_->Load();
  pdr_->Load();
  far_->Load();
  urr_->Load();
  bar_->Load();
  mar_->Load();
  Logger::upf_app().info("UPF_XDPProgram: all stage programs loaded");

  /* Step 7: Load remaining entry skeletons */
  if (xdp_n6_entry_kern_c__load(skel_n6_) != 0)
    throw std::runtime_error("Failed to load xdp_n6_entry");
  if (xdp_n3_eth_entry_kern_c__load(skel_n3_eth_) != 0)
    throw std::runtime_error("Failed to load xdp_n3_eth_entry");
  if (xdp_n6_eth_entry_kern_c__load(skel_n6_eth_) != 0)
    throw std::runtime_error("Failed to load xdp_n6_eth_entry");

  /* Step 10: Wrap N3's infrastructure map FDs in BPFMap objects */
  InitializeMaps();

  /* Step 11: Configure interface maps */
  uint32_t uplink_key   = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlink_key = static_cast<uint32_t>(FlowDirection::DOWNLINK);
  uint32_t n6_ifindex   = if_nametoindex(non_gtp_interface_.c_str());
  uint32_t n3_ifindex   = if_nametoindex(gtp_interface_.c_str());
  if (!n6_ifindex || !n3_ifindex)
    throw std::runtime_error("UPF_XDPProgram: interface index lookup failed");

  egress_interface_map_->Update(uplink_key, n6_ifindex, BPF_ANY);
  egress_interface_map_->Update(downlink_key, n3_ifindex, BPF_ANY);

  CreateUpfInterfaceMapEntry(N3_INTERFACE);
  CreateUpfInterfaceMapEntry(N6_INTERFACE);
  CreateUpfInterfaceMapEntry(N4_INTERFACE);

  /* Step 10: Attach entry programs -- PDU type controls which ones */
  if (flags.pdu_type == PduSessionType::Ethernet) {
    Logger::upf_app().debug("UPF_XDPProgram: attaching ETH PDU entry programs");
    if (xdp_n3_eth_entry_kern_c__attach(skel_n3_eth_) != 0)
      throw std::runtime_error("Failed to attach xdp_n3_eth_entry");
    if (xdp_n6_eth_entry_kern_c__attach(skel_n6_eth_) != 0)
      throw std::runtime_error("Failed to attach xdp_n6_eth_entry");
  } else {
    Logger::upf_app().debug("UPF_XDPProgram: attaching IP PDU entry programs");
    if (xdp_n3_entry_kern_c__attach(skel_n3_) != 0)
      throw std::runtime_error("Failed to attach xdp_n3_entry");
    if (xdp_n6_entry_kern_c__attach(skel_n6_) != 0)
      throw std::runtime_error("Failed to attach xdp_n6_entry");
  }

  /* Step 11: Populate tail_call_progs_map */
  PopulateProgramArray(flags);

  Logger::upf_app().info("UPF_XDPProgram: Setup complete");
}

/* Section: PROG_ARRAY population */

//------------------------------------------------------------------------------
void UPF_XDPProgram::PopulateProgramArray(const PipelineFeatureFlags& flags) {
  if (flags.pdu_type == PduSessionType::Ethernet)
    InsertProgramSlot(PROG_SESSION_LOOKUP_ETH, sl_eth_->GetXdpProgram());
  else
    InsertProgramSlot(PROG_SESSION_LOOKUP_IP, sl_ip_->GetXdpProgram());

  InsertProgramSlot(PROG_PDR_MATCH, pdr_->GetXdpProgram());
  InsertProgramSlot(PROG_FAR_APPLY, far_->GetXdpProgram());

  if (flags.enable_urr)
    InsertProgramSlot(PROG_URR_APPLY, urr_->GetXdpProgram());
  if (flags.enable_bar)
    InsertProgramSlot(PROG_BAR_APPLY, bar_->GetXdpProgram());
  if (flags.enable_mar)
    InsertProgramSlot(PROG_MAR_APPLY, mar_->GetXdpProgram());

  Logger::upf_app().info("PopulateProgramArray: complete");
}

//------------------------------------------------------------------------------
bool UPF_XDPProgram::InsertProgramSlot(
    uint32_t index, struct bpf_program* prog) {
  if (!prog || !tail_call_progs_map_) return false;
  int fd = bpf_program__fd(prog);
  if (fd < 0) return false;
  if (tail_call_progs_map_->Update(index, fd, BPF_ANY) != 0) {
    Logger::upf_app().error("InsertProgramSlot: failed slot %u", index);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
/* Section: TearDown
 * Entry programs are torn down by their lifecycle_ destructors when
 * n3_, n6_, n3_eth_, n6_eth_ shared_ptrs are reset.
 * lifecycle_->tearDown() is called by ProgramLifeCycle destructor. */

void UPF_XDPProgram::TearDown() {
  /* Reset stage programs first */
  mar_    = nullptr;
  bar_    = nullptr;
  urr_    = nullptr;
  qer_    = nullptr;
  far_    = nullptr;
  pdr_    = nullptr;
  sl_eth_ = nullptr;
  sl_ip_  = nullptr;

  if (skel_n6_eth_) {
    xdp_n6_eth_entry_kern_c__destroy(skel_n6_eth_);
    skel_n6_eth_ = nullptr;
  }
  if (skel_n3_eth_) {
    xdp_n3_eth_entry_kern_c__destroy(skel_n3_eth_);
    skel_n3_eth_ = nullptr;
  }
  if (skel_n6_) {
    xdp_n6_entry_kern_c__destroy(skel_n6_);
    skel_n6_ = nullptr;
  }
  if (skel_n3_) {
    xdp_n3_entry_kern_c__destroy(skel_n3_);
    skel_n3_ = nullptr;
  }

  Logger::upf_app().info("UPF_XDPProgram: TearDown complete");
}

/* Section: Map initialization */

//------------------------------------------------------------------------------
void UPF_XDPProgram::InitializeMaps() {
  /*
   * Wrap only the 7 infrastructure maps from n3_entry skeleton.
   * All other maps are owned by their respective stage programs.
   */
  maps_ = std::make_shared<BPFMaps>(skel_n3_->skeleton);

  auto get = [&](const char* name) -> std::shared_ptr<BPFMap> {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };

  packet_ctx_map_       = get("packet_context_map");
  tail_call_progs_map_  = get("tail_call_progs_map");
  upf_iface_map_        = get("upf_interface_map");
  egress_interface_map_ = get("redirect_interfaces_map");
  arp_table_map_        = get("arp_table_map");
  session_rules_map_    = get("session_rules_enabled_map");
  mc_stats_map_         = get("mc_stats");

  Logger::upf_app().info("UPF_XDPProgram: InitializeMaps complete (7 maps)");

  /* Inject map references into stage programs */
  pdr_->SetMaps(
      sl_ip_->GetSessionPdrsMap(), sl_ip_->GetRulesMatchMap(), sl_ip_->GetSessionPdrsMap() /* sdf is pdr-owned, set via GetSdfFilterMap below */);
  /* NOTE: pdr_ sdf_filter_map is owned by pdr_ skeleton itself -- no injection
   * needed */
}

/* Section: Interface configuration */

//------------------------------------------------------------------------------
void UPF_XDPProgram::CreateUpfInterfaceMapEntry(reference_point_t s) {
  struct interface_config iface;
  __builtin_memset(&iface, 0, sizeof(iface));

  switch (s) {
    case N3_INTERFACE:
      iface.ipv4_address = upf::GetN3Ip();
      iface.port         = upf::GetN3Port();
      iface.if_name      = upf::GetN3Iface().c_str();
      upf_iface_map_->Update(s, iface, BPF_ANY);
      break;
    case N6_INTERFACE:
      iface.ipv4_address = upf::GetN6Ip();
      iface.port         = 0;
      iface.if_name      = upf::GetN6Iface().c_str();
      upf_iface_map_->Update(s, iface, BPF_ANY);
      break;
    case N4_INTERFACE:
      iface.ipv4_address = upf::GetN4Ip();
      iface.port         = upf::GetN4Port();
      iface.if_name      = upf::GetN4Iface().c_str();
      upf_iface_map_->Update(s, iface, BPF_ANY);
      break;
    default:
      Logger::upf_app().error(
          "CreateUpfInterfaceMapEntry: unknown reference point %d", s);
  }
}

/* Section: GetMapByName */

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetMapByName(const std::string& n) {
  /* Infrastructure maps */
  if (n == "upf_interface_map") return upf_iface_map_;
  if (n == "redirect_interfaces_map") return egress_interface_map_;
  if (n == "arp_table" || n == "arp_table_map") return arp_table_map_;
  if (n == "tail_call_progs_map" || n == "feature_dispatch_map")
    return tail_call_progs_map_;
  if (n == "session_rules_enabled_map") return session_rules_map_;
  if (n == "packet_context_map") return packet_ctx_map_;
  if (n == "mc_stats_map" || n == "mc_stats") return mc_stats_map_;

  /* IP session maps -- SessionLookupIPProgram */
  if (n == "session_map" || n == "session_by_ue_ip_map")
    return sl_ip_ ? sl_ip_->GetSessionByUeIpMap() : nullptr;
  if (n == "pdrs_per_session_map")
    return sl_ip_ ? sl_ip_->GetSessionPdrsMap() : nullptr;
  if (n == "rules_match_pdr_map")
    return sl_ip_ ? sl_ip_->GetRulesMatchMap() : nullptr;
  if (n == "session_qos_enabled_map")
    return sl_ip_ ? sl_ip_->GetSessionQosEnabledMap() : nullptr;
  if (n == "m_framed_route_mapping")
    return sl_ip_ ? sl_ip_->GetFramedRouteMappingMap() : nullptr;
  if (n == "framed_routing_flag")
    return sl_ip_ ? sl_ip_->GetFramedRoutingFlagMap() : nullptr;

  /* ETH session maps -- SessionLookupETHProgram */
  if (n == "session_by_mac_map")
    return sl_eth_ ? sl_eth_->GetSessionByMacMap() : nullptr;
  if (n == "mac_pdu_session_map")
    return sl_eth_ ? sl_eth_->GetMacPduSessionMap() : nullptr;
  if (n == "eth_session_mapping_map")
    return sl_eth_ ? sl_eth_->GetEthSessionMappingMap() : nullptr;
  if (n == "eth_session_pdrs_map")
    return sl_eth_ ? sl_eth_->GetEthSessionPdrsMap() : nullptr;
  if (n == "eth_rules_match_pdr_map")
    return sl_eth_ ? sl_eth_->GetEthRulesMatchPdrMap() : nullptr;
  if (n == "eth_egress_ifindex_map")
    return sl_eth_ ? sl_eth_->GetEthEgressIfindexMap() : nullptr;

  /* PDR match maps */
  if (n == "sdf_filters_map") return pdr_ ? pdr_->GetSdfFilterMap() : nullptr;

  /* URR maps */
  if (n == "urr_config_map") return urr_ ? urr_->GetUrrConfigMap() : nullptr;
  if (n == "urr_volume_counters_map")
    return urr_ ? urr_->GetUrrVolumeMap() : nullptr;

  /* BAR maps */
  if (n == "bar_config_map") return bar_ ? bar_->GetBarConfigMap() : nullptr;
  if (n == "bar_state_map") return bar_ ? bar_->GetBarStateMap() : nullptr;

  /* MAR maps */
  if (n == "mar_config_map") return mar_ ? mar_->GetMarConfigMap() : nullptr;
  if (n == "mar_access_state_map")
    return mar_ ? mar_->GetMarAccessStateMap() : nullptr;

  Logger::upf_app().warn("GetMapByName: '%s' not found", n.c_str());
  return nullptr;
}

/* Section: Framed routing */

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetFramedRouteMappingMap() {
  return sl_ip_ ? sl_ip_->GetFramedRouteMappingMap() : nullptr;
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::UpdateFramedRouteMappingMap(
    uint32_t ue_ip, FramedRoutingKeyBPF key) {
  auto m = GetFramedRouteMappingMap();
  if (m) {
    uint32_t k = hash_framed_routing_key(&key);
    m->Update(k, ue_ip, BPF_ANY);
  }
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::RemoveFramedRoute(FramedRoutingKeyBPF key) {
  auto m = GetFramedRouteMappingMap();
  if (m) {
    uint32_t k = hash_framed_routing_key(&key);
    uint32_t v;
    if (m->Lookup(k, &v) == 0) m->Remove(k);
  }
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::SetFramedRouting(bool enable) {
  auto m = sl_ip_ ? sl_ip_->GetFramedRoutingFlagMap() : nullptr;
  if (m) {
    uint8_t v = enable ? 1 : 0, k = 0;
    m->Update(k, v, BPF_ANY);
  }
}

/* Section: RemoveProgramMap */

//------------------------------------------------------------------------------
void UPF_XDPProgram::RemoveProgramMap(uint32_t key) {
  if (tail_call_progs_map_) tail_call_progs_map_->Remove(key);
}

/* Section: Delegated map getters */

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> UPF_XDPProgram::GetMaps() {
  return maps_;
}
size_t UPF_XDPProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}
bool UPF_XDPProgram::IsNativeXdp(const std::string&) const {
  return true;
}
std::string UPF_XDPProgram::GetXdpModeString(const std::string& iface) const {
  return IsNativeXdp(iface) ? "Native" : "SKB";
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSessionMappingMap() const {
  return sl_ip_ ? sl_ip_->GetSessionByUeIpMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSessionMacMap() const {
  return sl_eth_ ? sl_eth_->GetSessionByMacMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetRulesMatchPdrMap() const {
  return sl_ip_ ? sl_ip_->GetRulesMatchMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSessionPdrsMap() const {
  return sl_ip_ ? sl_ip_->GetSessionPdrsMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSdfFilterMap() const {
  return pdr_ ? pdr_->GetSdfFilterMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetQosEnablingMap() const {
  return sl_ip_ ? sl_ip_->GetSessionQosEnabledMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetFeatureDispatchMap() const {
  return tail_call_progs_map_;
}
