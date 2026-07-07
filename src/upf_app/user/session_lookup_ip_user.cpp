/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "session_lookup_ip_user.h"
#include <bpf/libbpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_xdp_limits.h"
#include "utils/bpf_utils.hpp"

using namespace oai::utils::bpf;

//------------------------------------------------------------------------------
void SessionLookupIPProgram::ConfigureMaps(
    struct xdp_session_lookup_ip_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error(
        "Null skeleton in SessionLookupIPProgram::ConfigureMaps");
    return;
  }

  bool ok = true;

  /* pipeline_maps.h -- runtime-sized maps */
  ok &= ConfigureMapMaxEntries(
      skel->maps.session_by_ue_ip_map, "session_by_ue_ip_map",
      upf::GetMaxPduSessions());

  ok &= ConfigureMapMaxEntries(
      skel->maps.pdrs_per_session_map, "pdrs_per_session_map",
      upf::GetMaxPduSessions());

  ok &= ConfigureMapMaxEntries(
      skel->maps.session_qos_enabled_map, "session_qos_enabled_map",
      upf::GetMaxPduSessions());

  ok &= ConfigureMapMaxEntries(
      skel->maps.rules_match_pdr_map, "rules_match_pdr_map",
      upf::GetMaxPduSessions() * upf::GetMaxPdrsPerSession());

  ok &= ConfigureMapMaxEntries(
      skel->maps.m_framed_route_mapping, "m_framed_route_mapping",
      upf::GetMaxPduSessions());

  /*
   * framed_routing_flag: BPF_MAP_TYPE_ARRAY, max_entries=1 (boolean flag).
   * feature_dispatch_map: BPF_MAP_TYPE_PROG_ARRAY, tail-call table.
   * tail_call_progs_map, packet_context_map, session_rules_enabled_map:
   *   fixed size or shared from primary (n3_entry) via bpf_map__reuse_fd.
   * No runtime sizing needed for these.
   */

  if (!ok) {
    Logger::upf_app().error(
        "One or more map configurations failed for SessionLookupIPProgram.");
    throw std::runtime_error("SessionLookupIPProgram map configuration failed");
  }

  /* rodata: all 7 fields */
  if (skel->rodata) {
    skel->rodata->MAX_UPF_INTERFACES = upf::GetMaxUpfInterfaces();
    skel->rodata->MAX_UPF_REDIRECT_INTERFACES =
        upf::GetMaxUpfRedirectInterfaces();
    skel->rodata->MAX_PDU_SESSIONS         = upf::GetMaxPduSessions();
    skel->rodata->MAX_PDRS_PER_PDU_SESSION = upf::GetMaxPdrsPerSession();
    skel->rodata->MAX_SDF_FILTERS_PER_PDU_SESSION =
        upf::GetMaxSdfFiltersPerSession();
    skel->rodata->MAX_ARP_ENTRIES  = upf::GetMaxArpEntries();
    skel->rodata->MAX_QOS_ENABLING = upf::GetMaxPduSessions();
  }
}

//------------------------------------------------------------------------------
SessionLookupIPProgram::SessionLookupIPProgram() : BPFProgram() {
  Logger::upf_app().debug("Initializing SessionLookupIP XDP Program ...");

  auto open_fn = [this]() -> xdp_session_lookup_ip_kern_c* {
    struct xdp_session_lookup_ip_kern_c* s =
        xdp_session_lookup_ip_kern_c__open();
    if (!s) {
      Logger::upf_app().error("Failed to open xdp_session_lookup_ip skeleton");
      return nullptr;
    }
    // Configure maps and rodata before skeleton is loaded
    this->ConfigureMaps(s);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = s;
    return s;
  };

  lifecycle_ = std::make_shared<SessionLookupIPLifeCycle>(
      open_fn,
      /* load    */ xdp_session_lookup_ip_kern_c__load,
      /* attach  */ xdp_session_lookup_ip_kern_c__attach,
      /* destroy */ xdp_session_lookup_ip_kern_c__destroy,
      "SessionLookupIPProgram");
}

//------------------------------------------------------------------------------
SessionLookupIPProgram::~SessionLookupIPProgram() {}

//------------------------------------------------------------------------------
void SessionLookupIPProgram::Setup() {
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
void SessionLookupIPProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void SessionLookupIPProgram::InitializeMaps() {
  maps_    = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);
  auto get = [&](const char* name) {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };
  /* pipeline_maps.h */
  session_by_ue_ip_map_     = get("session_by_ue_ip_map");
  pdrs_per_session_map_     = get("pdrs_per_session_map");
  session_qos_enabled_map_  = get("session_qos_enabled_map");
  rules_match_pdr_map_      = get("rules_match_pdr_map");
  framed_route_mapping_map_ = get("m_framed_route_mapping");
  framed_routing_flag_map_  = get("framed_routing_flag");
  feature_dispatch_map_     = get("feature_dispatch_map");
  /* tail_call_dispatcher.h -- shared from primary (n3_ or n3_eth_) */
  tail_call_progs_map_       = get("tail_call_progs_map");
  packet_ctx_map_            = get("packet_context_map");
  session_rules_enabled_map_ = get("session_rules_enabled_map");
}

//------------------------------------------------------------------------------
struct bpf_object* SessionLookupIPProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* SessionLookupIPProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* SessionLookupIPProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.session_lookup_ip : nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> SessionLookupIPProgram::GetMaps() const {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetSessionByUeIpMap() const {
  return session_by_ue_ip_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetSessionPdrsMap() const {
  return pdrs_per_session_map_;
}
//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetSessionQosEnabledMap()
    const {
  return session_qos_enabled_map_;
}
//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetRulesMatchMap() const {
  return rules_match_pdr_map_;
}
//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetFramedRouteMappingMap()
    const {
  return framed_route_mapping_map_;
}
//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetFramedRoutingFlagMap()
    const {
  return framed_routing_flag_map_;
}
//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetFeatureDispatchMap() const {
  return feature_dispatch_map_;
}

/* Section: Map accessors -- tail_call_dispatcher.h */

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetTailCallProgsMap() const {
  return tail_call_progs_map_;
}
//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetPacketContextMap() const {
  return packet_ctx_map_;
}
//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetSessionRulesEnabledMap()
    const {
  return session_rules_enabled_map_;
}

/* Section: Utility */

//------------------------------------------------------------------------------
size_t SessionLookupIPProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}
