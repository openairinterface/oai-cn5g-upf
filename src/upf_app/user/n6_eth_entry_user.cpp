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
 * Changes:     New file. Mirrors n3_entry_user.cpp in structure.
 *              Unlike the other entry programs, ConfigureMaps() here performs
 *              real runtime sizing for interfaces_maps.h and eth_pdu_maps.h.
 *              Setup() also populates redirect_interfaces_map and
 *              upf_interface_map after load.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol
 *              3GPP TS 23.501          -- 5G System Architecture
 */
// clang-format on

#include "n6_eth_entry_user.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "interfaces_types.h"
#include "upf_xdp_limits.h"
#include "xdp_hook_section.h"
#include "utils/net_utils.hpp"
#include "utils/bpf_utils.hpp"

using namespace oai::utils::net;
using namespace oai::utils::bpf;

//------------------------------------------------------------------------------
void N6EthEntryProgram::ConfigureMaps(struct xdp_n6_eth_entry_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in ConfigureMaps");
    return;
  }

  // Validate configuration against system limits
  int num_ifaces = CountAvailableInterfaces();
  if (upf::GetMaxUpfInterfaces() > static_cast<uint32_t>(num_ifaces)) {
    Logger::upf_app().warn(
        "Configured max_upf_interfaces (%u) exceeds available system "
        "interfaces (%d). Clamping to %d.",
        upf::GetMaxUpfInterfaces(), num_ifaces, num_ifaces);
  }

  if (upf::GetMaxUpfRedirectInterfaces() > upf::GetMaxUpfInterfaces()) {
    Logger::upf_app().error(
        "Invalid config: max_upf_redirect_interfaces (%u) cannot exceed "
        "max_upf_interfaces (%u).",
        upf::GetMaxUpfRedirectInterfaces(), upf::GetMaxUpfInterfaces());
    throw std::runtime_error(
        "Invalid UPF configuration (redirect > interfaces)");
  }

  if (upf::GetMaxPdrsPerSession() > MAX_PDRS_PER_PDU_SESSION_LIMIT) {
    Logger::upf_app().error(
        "Configuration error: max_pdrs_per_pdu_session (%u) exceeds "
        "compile-time limit (%u). Please recompile with a larger "
        "MAX_PDRS_PER_PDU_SESSION_LIMIT or reduce your configuration.",
        upf::GetMaxPdrsPerSession(), MAX_PDRS_PER_PDU_SESSION_LIMIT);
    throw std::runtime_error(
        "max_pdrs_per_pdu_session exceeds compile-time limit");
  }

  // if (upf::GetMaxPduSessions() > upf::GetMaxUes()) {
  //   Logger::upf_app().error(
  //       "Configuration error: max_pdu_sessions (%u) exceeds "
  //       "max_ues (%u). Each UE can have at most one PDU session "
  //       "in the current configuration.",
  //       upf::GetMaxPduSessions(), upf::GetMaxUes());
  //   throw std::runtime_error("max_pdu_sessions exceeds max_ues");
  // }

  bool ok = true;

  /* interfaces_maps.h -- upf_interface_map and redirect_interfaces_map
   * are owned and sized by FARProgram. Do NOT size them here. */

  /* eth_pdu_maps.h */
  ok &= ConfigureMapMaxEntries(
      skel->maps.session_by_mac_map, "session_by_mac_map",
      upf::GetMaxPduSessions());

  ok &= ConfigureMapMaxEntries(
      skel->maps.eth_session_mapping_map, "eth_session_mapping_map",
      upf::GetMaxPduSessions());

  ok &= ConfigureMapMaxEntries(
      skel->maps.eth_session_pdrs_map, "eth_session_pdrs_map",
      upf::GetMaxPduSessions());

  ok &= ConfigureMapMaxEntries(
      skel->maps.eth_rules_match_pdr_map, "eth_rules_match_pdr_map",
      upf::GetMaxPduSessions() * upf::GetMaxPdrsPerSession());

  ok &= ConfigureMapMaxEntries(
      skel->maps.eth_egress_ifindex_map, "eth_egress_ifindex_map",
      upf::GetMaxUpfInterfaces());

  // ok &= ConfigureMapMaxEntries(
  //     skel->maps.mac_pdu_session_map, "mac_pdu_session_map",
  //     upf::GetMaxUes());

  if (!ok) {
    Logger::upf_app().error(
        "One or more BPF map configurations failed for N6EthEntryProgram.");
    throw std::runtime_error("N6EthEntryProgram map configuration failed");
  }

  /* rodata: MAX_UPF_INTERFACES (only field confirmed from skeleton grep) */
  if (skel->rodata)
    skel->rodata->MAX_UPF_INTERFACES = upf::GetMaxUpfInterfaces();
  skel->rodata->MAX_UPF_REDIRECT_INTERFACES =
      upf::GetMaxUpfRedirectInterfaces();
  skel->rodata->MAX_PDU_SESSIONS         = upf::GetMaxPduSessions();
  skel->rodata->MAX_PDRS_PER_PDU_SESSION = upf::GetMaxPdrsPerSession();
  // skel->rodata->MAX_USER_EQUIPMENTS      = upf::GetMaxUes();
}

//------------------------------------------------------------------------------
N6EthEntryProgram::N6EthEntryProgram(const std::string& non_gtp_interface)
    : BPFProgram(), non_gtp_interface_(non_gtp_interface) {
  Logger::upf_app().debug("Initializing N6 ETH Entry XDP Program ...");

  auto open_fn = [this]() -> xdp_n6_eth_entry_kern_c* {
    struct xdp_n6_eth_entry_kern_c* skel = xdp_n6_eth_entry_kern_c__open();
    if (!skel) {
      Logger::upf_app().error("Failed to open xdp_n6_eth_entry skeleton");
      return nullptr;
    }

    this->ConfigureMaps(skel);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = skel;
    return skel;
  };

  lifecycle_ = std::make_shared<N6EthEntryLifeCycle>(
      open_fn,
      /* load    */ xdp_n6_eth_entry_kern_c__load,
      /* attach  */ xdp_n6_eth_entry_kern_c__attach,
      /* destroy */ xdp_n6_eth_entry_kern_c__destroy, "N6EthEntryProgram");
}

//------------------------------------------------------------------------------
N6EthEntryProgram::~N6EthEntryProgram() {}

//------------------------------------------------------------------------------
void N6EthEntryProgram::Setup() {
  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
  lifecycle_->attach();

  /* Populate redirect_interfaces_map with interface indices */
  uint32_t n3_ifindex = if_nametoindex(upf::GetN3Iface().c_str());
  uint32_t n6_ifindex = if_nametoindex(upf::GetN6Iface().c_str());

  uint32_t uplink_key   = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlink_key = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  redirect_interfaces_map_->Update(uplink_key, n6_ifindex, BPF_ANY);
  redirect_interfaces_map_->Update(downlink_key, n3_ifindex, BPF_ANY);

  /* upf_interface_map is populated by
   * UPF_XDPProgram::CreateUpfInterfaceMapEntry after all programs are loaded.
   * Do NOT populate it here. */

  Logger::upf_app().debug(
      "Link N6 ETH Entry XDP to interface %s", non_gtp_interface_.c_str());
  lifecycle_->link(
      XDPSection::Downlink_ETH_PDU_SESSION, non_gtp_interface_.c_str());
}

//------------------------------------------------------------------------------
void N6EthEntryProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void N6EthEntryProgram::InitializeMaps() {
  maps_    = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);
  auto get = [&](const char* name) {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };
  /* interfaces_maps.h */
  upf_interface_map_       = get("upf_interface_map");
  redirect_interfaces_map_ = get("redirect_interfaces_map");
  /* eth_pdu_maps.h */
  session_by_mac_map_      = get("session_by_mac_map");
  eth_session_mapping_map_ = get("eth_session_mapping_map");
  eth_session_pdrs_map_    = get("eth_session_pdrs_map");
  eth_rules_match_pdr_map_ = get("eth_rules_match_pdr_map");
  eth_egress_ifindex_map_  = get("eth_egress_ifindex_map");
  mac_pdu_session_map_     = get("mac_pdu_session_map");
  /* stats_maps.h */
  mc_stats_map_ = get("mc_stats_map");
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N6EthEntryProgram::GetMapByName(
    const std::string& map_name) {
  if (map_name == "upf_interface_map") return upf_interface_map_;
  if (map_name == "redirect_interfaces_map") return redirect_interfaces_map_;
  if (map_name == "session_by_mac_map") return session_by_mac_map_;
  if (map_name == "eth_session_mapping_map") return eth_session_mapping_map_;
  if (map_name == "eth_session_pdrs_map") return eth_session_pdrs_map_;
  if (map_name == "eth_rules_match_pdr_map") return eth_rules_match_pdr_map_;
  if (map_name == "eth_egress_ifindex_map") return eth_egress_ifindex_map_;
  if (map_name == "mac_pdu_session_map") return mac_pdu_session_map_;
  if (map_name == "mc_stats_map") return mc_stats_map_;

  Logger::upf_app().warn(
      "Map '%s' not found in N6EthEntryProgram", map_name.c_str());
  return nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> N6EthEntryProgram::GetMaps() {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N6EthEntryProgram::GetRedirectInterfacesMap() const {
  return redirect_interfaces_map_;
}
std::shared_ptr<BPFMap> N6EthEntryProgram::GetSessionByMacMap() const {
  return session_by_mac_map_;
}
std::shared_ptr<BPFMap> N6EthEntryProgram::GetEthSessionMappingMap() const {
  return eth_session_mapping_map_;
}
std::shared_ptr<BPFMap> N6EthEntryProgram::GetEthSessionPdrsMap() const {
  return eth_session_pdrs_map_;
}
std::shared_ptr<BPFMap> N6EthEntryProgram::GetEthRulesMatchPdrMap() const {
  return eth_rules_match_pdr_map_;
}
std::shared_ptr<BPFMap> N6EthEntryProgram::GetEthEgressIfindexMap() const {
  return eth_egress_ifindex_map_;
}
std::shared_ptr<BPFMap> N6EthEntryProgram::GetMcStatsMap() const {
  return mc_stats_map_;
}
std::shared_ptr<BPFMap> N6EthEntryProgram::GetMacPduSessionMap() const {
  return mac_pdu_session_map_;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): See TODO in n3_entry_user.cpp -- GetMapCount() ownership.
 */
size_t N6EthEntryProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): See TODO in n3_entry_user.cpp -- IsNativeXdp and
 * GetXdpModeString should be removed once UPF_XDPProgram exposes them.
 */
bool N6EthEntryProgram::IsNativeXdp(const std::string& interface) const {
  if (!lifecycle_) return false;
  return lifecycle_->IsNativeXdp(interface);
}

//------------------------------------------------------------------------------
std::string N6EthEntryProgram::GetXdpModeString(
    const std::string& interface) const {
  if (!lifecycle_) return "Unknown";
  return lifecycle_->GetXdpModeString(interface);
}

//------------------------------------------------------------------------------
struct bpf_object* N6EthEntryProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* N6EthEntryProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}
