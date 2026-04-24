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
 * Changes:     New file. Mirrors session_lookup_ip_user.cpp exactly in
 *              structure. Manages only what xdp_session_lookup_eth_kern.c uses.
 *              Setup() = open (idempotent) + InitializeMaps + load.
 *              No attach() / link() -- stage program, reached via tail call.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol
 *              3GPP TS 23.501 §5.6.10.3 -- Ethernet PDU Session Type
 */
// clang-format on

#include "session_lookup_eth_user.h"
#include <bpf/libbpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_xdp_limits.h"
#include "utils/bpf_utils.hpp"

using namespace oai::utils::bpf;

//------------------------------------------------------------------------------
void SessionLookupETHProgram::ConfigureMaps(
    struct xdp_session_lookup_eth_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error(
        "Null skeleton in SessionLookupETHProgram::ConfigureMaps");
    return;
  }

  bool ok = true;

  /* eth_pdu_maps.h -- runtime-sized maps */
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

  ok &= ConfigureMapMaxEntries(
      skel->maps.mac_pdu_session_map, "mac_pdu_session_map",
      upf::GetMaxPduSessions());

  /*
   * tail_call_progs_map, packet_context_map, session_rules_enabled_map:
   *   fixed size or shared from primary (n3_eth_entry) via bpf_map__reuse_fd.
   * No runtime sizing needed for these.
   */

  if (!ok) {
    Logger::upf_app().error(
        "One or more map configurations failed for "
        "SessionLookupETHProgram.");
    throw std::runtime_error(
        "SessionLookupETHProgram map configuration failed");
  }

  /* rodata: 4 fields (eth_pdu_maps.h declares MAX_UPF_INTERFACES,
   * MAX_PDU_SESSIONS, MAX_PDRS_PER_PDU_SESSION,
   * MAX_UPF_REDIRECT_INTERFACES) */
  if (skel->rodata) {
    skel->rodata->MAX_UPF_INTERFACES = upf::GetMaxUpfInterfaces();
    skel->rodata->MAX_UPF_REDIRECT_INTERFACES =
        upf::GetMaxUpfRedirectInterfaces();
    skel->rodata->MAX_PDU_SESSIONS         = upf::GetMaxPduSessions();
    skel->rodata->MAX_PDRS_PER_PDU_SESSION = upf::GetMaxPdrsPerSession();
  }
}

//------------------------------------------------------------------------------
SessionLookupETHProgram::SessionLookupETHProgram() : BPFProgram() {
  Logger::upf_app().debug("Initializing SessionLookupETH XDP Program ...");

  auto open_fn = [this]() -> xdp_session_lookup_eth_kern_c* {
    struct xdp_session_lookup_eth_kern_c* s =
        xdp_session_lookup_eth_kern_c__open();
    if (!s) {
      Logger::upf_app().error("Failed to open xdp_session_lookup_eth skeleton");
      return nullptr;
    }
    // Configure maps and rodata before skeleton is loaded
    this->ConfigureMaps(s);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = s;
    return s;
  };

  lifecycle_ = std::make_shared<SessionLookupETHLifeCycle>(
      open_fn,
      /* load    */ xdp_session_lookup_eth_kern_c__load,
      /* attach  */ xdp_session_lookup_eth_kern_c__attach,
      /* destroy */ xdp_session_lookup_eth_kern_c__destroy,
      "SessionLookupETHProgram");
}

//------------------------------------------------------------------------------
SessionLookupETHProgram::~SessionLookupETHProgram() {}

//------------------------------------------------------------------------------
void SessionLookupETHProgram::Setup() {
  /*
   * lifecycle_->open() is idempotent: if UPF_XDPProgram already called it
   * (to get the bpf_object for ShareMaps before loading), this returns the
   * cached skeleton with no side effects.
   */
  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
}

//------------------------------------------------------------------------------
void SessionLookupETHProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void SessionLookupETHProgram::InitializeMaps() {
  maps_    = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);
  auto get = [&](const char* name) {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };
  /* eth_pdu_maps.h */
  session_by_mac_map_      = get("session_by_mac_map");
  eth_session_mapping_map_ = get("eth_session_mapping_map");
  eth_session_pdrs_map_    = get("eth_session_pdrs_map");
  eth_rules_match_pdr_map_ = get("eth_rules_match_pdr_map");
  eth_egress_ifindex_map_  = get("eth_egress_ifindex_map");
  mac_pdu_session_map_     = get("mac_pdu_session_map");
  /* pipeline_maps.h -- shared from primary (n3_eth_) via reuse_fd */
  feature_dispatch_map_ = get("feature_dispatch_map");
  /* tail_call_dispatcher.h -- shared from primary (n3_eth_) via reuse_fd */
  tail_call_progs_map_       = get("tail_call_progs_map");
  packet_ctx_map_            = get("packet_context_map");
  session_rules_enabled_map_ = get("session_rules_enabled_map");
}

//------------------------------------------------------------------------------
struct bpf_object* SessionLookupETHProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* SessionLookupETHProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* SessionLookupETHProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.session_lookup_eth : nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> SessionLookupETHProgram::GetMaps() const {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetSessionByMacMap() const {
  return session_by_mac_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetEthSessionMappingMap()
    const {
  return eth_session_mapping_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetEthSessionPdrsMap() const {
  return eth_session_pdrs_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetEthRulesMatchPdrMap()
    const {
  return eth_rules_match_pdr_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetEthEgressIfindexMap()
    const {
  return eth_egress_ifindex_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetMacPduSessionMap() const {
  return mac_pdu_session_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetFeatureDispatchMap() const {
  return feature_dispatch_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetTailCallProgsMap() const {
  return tail_call_progs_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetPacketContextMap() const {
  return packet_ctx_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetSessionRulesEnabledMap()
    const {
  return session_rules_enabled_map_;
}

//------------------------------------------------------------------------------
size_t SessionLookupETHProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}
