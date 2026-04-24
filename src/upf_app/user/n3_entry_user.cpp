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
 * Changes:     New file. Manages only what xdp_n3_entry_kern.c uses.
 *              Duplicate GetMapCount() removed (was defined twice).
 *              IsNativeXdp/GetXdpModeString kept with TODO noting future
 *              relocation to a shared XDP base class.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol
 *              3GPP TS 23.501          -- 5G System Architecture
 */
// clang-format on

#include "n3_entry_user.h"
#include <bpf/libbpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "xdp_hook_section.h"
#include "upf_xdp_limits.h"
#include "utils/bpf_utils.hpp"

using namespace oai::utils::bpf;

//------------------------------------------------------------------------------
void N3EntryProgram::ConfigureMaps(struct xdp_n3_entry_kern_c* skel) {
  if (!skel) return;

  /* n3_ owns session_rules_enabled_map (defined in tail_call_maps.h).
   * Size it before load so ShareMaps gives all other programs
   * a correctly-sized instance. */
  ConfigureMapMaxEntries(
      skel->maps.session_rules_enabled_map, "session_rules_enabled_map",
      upf::GetMaxPduSessions());

  /* rodata bounds constants (used by BPF program for bounds checking only,
   * NOT for map sizing -- see upf_map_limits.h). */
  if (skel->rodata) {
    skel->rodata->MAX_UPF_INTERFACES = upf::GetMaxUpfInterfaces();
    skel->rodata->MAX_UPF_REDIRECT_INTERFACES =
        upf::GetMaxUpfRedirectInterfaces();
    skel->rodata->MAX_ARP_ENTRIES  = upf::GetMaxArpEntries();
    skel->rodata->MAX_PDU_SESSIONS = upf::GetMaxPduSessions();
  }
}

//------------------------------------------------------------------------------
N3EntryProgram::N3EntryProgram(const std::string& gtp_interface)
    : BPFProgram(), gtp_interface_(gtp_interface) {
  Logger::upf_app().debug("Initializing N3 Entry XDP Program ...");

  auto open_fn = [this]() -> xdp_n3_entry_kern_c* {
    struct xdp_n3_entry_kern_c* skel = xdp_n3_entry_kern_c__open();
    if (!skel) {
      Logger::upf_app().error("Failed to open xdp_n3_entry skeleton");
      return nullptr;
    }

    // Configure maps and rodata
    this->ConfigureMaps(skel);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = skel;
    return skel;
  };

  // Initialize lifecycle management
  lifecycle_ = std::make_shared<N3EntryLifeCycle>(
      open_fn,
      /* load    */ xdp_n3_entry_kern_c__load,
      /* attach  */ xdp_n3_entry_kern_c__attach,
      /* destroy */ xdp_n3_entry_kern_c__destroy, "N3EntryProgram");
}

//------------------------------------------------------------------------------
N3EntryProgram::~N3EntryProgram() {}

//------------------------------------------------------------------------------
void N3EntryProgram::Setup() {
  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
  lifecycle_->attach();
  Logger::upf_app().debug(
      "Link N3 Entry XDP to interface %s", gtp_interface_.c_str());
  lifecycle_->link(XDPSection::Uplink_IP_PDU_SESSION, gtp_interface_.c_str());
}

//------------------------------------------------------------------------------
void N3EntryProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void N3EntryProgram::InitializeMaps() {
  // Store all maps available in the program
  maps_    = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);
  auto get = [&](const char* name) {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };

  tail_call_progs_map_       = get("tail_call_progs_map");
  packet_ctx_map_            = get("packet_context_map");
  session_rules_enabled_map_ = get("session_rules_enabled_map");
  mc_stats_map_              = get("mc_stats_map");
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N3EntryProgram::GetMapByName(
    const std::string& map_name) {
  if (map_name == "tail_call_progs_map") return tail_call_progs_map_;
  if (map_name == "packet_context_map") return packet_ctx_map_;
  if (map_name == "session_rules_enabled_map")
    return session_rules_enabled_map_;
  if (map_name == "mc_stats_map") return mc_stats_map_;

  // Map not found
  Logger::upf_app().warn(
      "Map '%s' not found in N3EntryProgram", map_name.c_str());
  return nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> N3EntryProgram::GetMaps() {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N3EntryProgram::GetTailCallProgsMap() const {
  return tail_call_progs_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N3EntryProgram::GetPacketContextMap() const {
  return packet_ctx_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N3EntryProgram::GetSessionRulesEnabledMap() const {
  return session_rules_enabled_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N3EntryProgram::GetMcStatsMap() const {
  return mc_stats_map_;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): GetMapCount() should not live per-program if the goal is
 * to report a global map count for the whole pipeline. Two options:
 *   A) Keep it per-program and rename: GetOwnedMapCount().
 *   B) Remove it from program classes entirely and compute it in
 *      UPF_XDPProgram by summing over all program instances.
 * Proposed fix: see upf_xdp_user_updated.h/.cpp which moves the total count
 * to UPF_XDPProgram::GetTotalMapCount().
 */
size_t N3EntryProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): IsNativeXdp() and GetXdpModeString() do not belong in
 * individual program classes. They query the interface, not the program.
 * Since each interface has exactly one program attached (n3_entry or
 * n3_eth_entry on gtp_interface, n6_entry or n6_eth_entry on
 * non_gtp_interface), these queries belong in UPF_XDPProgram which knows
 * the interface assignment.
 * Proposed fix: see upf_xdp_user_updated.h/.cpp which exposes:
 *   UPF_XDPProgram::IsNativeXdp(const std::string& iface)
 *   UPF_XDPProgram::GetXdpModeString(const std::string& iface)
 * delegating to lifecycle_ of the attached program for that interface.
 * These functions should be REMOVED from all 4 entry program classes once
 * UPF_XDPProgram exposes them.
 */
bool N3EntryProgram::IsNativeXdp(const std::string& interface) const {
  if (!lifecycle_) return false;
  return lifecycle_->IsNativeXdp(interface);
}

//------------------------------------------------------------------------------
std::string N3EntryProgram::GetXdpModeString(
    const std::string& interface) const {
  if (!lifecycle_) return "Unknown";
  return lifecycle_->GetXdpModeString(interface);
}

//------------------------------------------------------------------------------

/*
 * TODO:
 *  I think we need to rework the class XdpStageProgram.
 *  and then inherit it in this class
 */
struct bpf_object* N3EntryProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* N3EntryProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}
