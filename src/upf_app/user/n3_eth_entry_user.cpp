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
 * Changes:     New file. Mirrors n3_entry_user.cpp exactly in structure.
 *              Manages only what xdp_n3_eth_entry_kern.c uses.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol
 *              3GPP TS 23.501          -- 5G System Architecture
 */
// clang-format on

#include "n3_eth_entry_user.h"
#include <bpf/libbpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "xdp_hook_section.h"

//------------------------------------------------------------------------------
void N3EthEntryProgram::ConfigureMaps(struct xdp_n3_eth_entry_kern_c* skel) {
  (void) skel;
  /*
   * All maps in xdp_n3_eth_entry_kern.c have fixed max_entries or are sized
   * by the owning program:
   *   stats_maps.h           -> mc_stats_map             (fixed)
   *   tail_call_dispatcher.h -> tail_call_progs_map       (fixed = 16)
   *                          -> packet_context_map        (fixed = 1)
   *                          -> session_rules_enabled_map (placeholder = 1,
   *                             sized by the program that owns it)
   * No runtime configuration needed here.
   */
}

//------------------------------------------------------------------------------
N3EthEntryProgram::N3EthEntryProgram(const std::string& gtp_interface)
    : BPFProgram(), gtp_interface_(gtp_interface) {
  Logger::upf_app().debug("Initializing N3 ETH Entry XDP Program ...");

  auto open_fn = [this]() -> xdp_n3_eth_entry_kern_c* {
    struct xdp_n3_eth_entry_kern_c* skel = xdp_n3_eth_entry_kern_c__open();
    if (!skel) {
      Logger::upf_app().error("Failed to open xdp_n3_eth_entry skeleton");
      return nullptr;
    }
    this->ConfigureMaps(skel);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = skel;
    return skel;
  };

  lifecycle_ = std::make_shared<N3EthEntryLifeCycle>(
      open_fn,
      /* load    */ xdp_n3_eth_entry_kern_c__load,
      /* attach  */ xdp_n3_eth_entry_kern_c__attach,
      /* destroy */ xdp_n3_eth_entry_kern_c__destroy, "N3EthEntryProgram");
}

//------------------------------------------------------------------------------
N3EthEntryProgram::~N3EthEntryProgram() {}

//------------------------------------------------------------------------------
void N3EthEntryProgram::Setup() {
  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
  lifecycle_->attach();
  Logger::upf_app().debug(
      "Link N3 ETH Entry XDP to interface %s", gtp_interface_.c_str());
  lifecycle_->link(XDPSection::Uplink_ETH_PDU_SESSION, gtp_interface_.c_str());
}

//------------------------------------------------------------------------------
void N3EthEntryProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void N3EthEntryProgram::InitializeMaps() {
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
std::shared_ptr<BPFMap> N3EthEntryProgram::GetMapByName(
    const std::string& map_name) {
  if (map_name == "tail_call_progs_map") return tail_call_progs_map_;
  if (map_name == "packet_context_map") return packet_ctx_map_;
  if (map_name == "session_rules_enabled_map")
    return session_rules_enabled_map_;
  if (map_name == "mc_stats_map") return mc_stats_map_;

  Logger::upf_app().warn(
      "Map '%s' not found in N3EthEntryProgram", map_name.c_str());
  return nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> N3EthEntryProgram::GetMaps() {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N3EthEntryProgram::GetTailCallProgsMap() const {
  return tail_call_progs_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N3EthEntryProgram::GetPacketContextMap() const {
  return packet_ctx_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N3EthEntryProgram::GetSessionRulesEnabledMap() const {
  return session_rules_enabled_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> N3EthEntryProgram::GetMcStatsMap() const {
  return mc_stats_map_;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): See TODO in n3_entry_user.cpp -- GetMapCount() ownership.
 */
size_t N3EthEntryProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): See TODO in n3_entry_user.cpp -- IsNativeXdp and
 * GetXdpModeString should be removed once UPF_XDPProgram exposes them.
 */
bool N3EthEntryProgram::IsNativeXdp(const std::string& interface) const {
  if (!lifecycle_) return false;
  return lifecycle_->IsNativeXdp(interface);
}

//------------------------------------------------------------------------------
std::string N3EthEntryProgram::GetXdpModeString(
    const std::string& interface) const {
  if (!lifecycle_) return "Unknown";
  return lifecycle_->GetXdpModeString(interface);
}

//------------------------------------------------------------------------------
struct bpf_object* N3EthEntryProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* N3EthEntryProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}
