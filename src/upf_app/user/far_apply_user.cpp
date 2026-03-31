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
 * Changes:     Rewritten to follow n3_entry_user.cpp / session_lookup_ip_user.cpp
 *              pattern exactly.
 *              Constructor no longer opens the skeleton -- open is lazy.
 *              ConfigureMaps uses ConfigureMapMaxEntries(skel->maps.xxx).
 *              FAR owns interfaces_maps.h + arp_maps.h; pipeline and ETH
 *              maps are shared via reuse_fd and not sized here.
 *              Setup() = open (idempotent) + InitializeMaps + load.
 *              No attach() / link() -- stage program, reached via tail call.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §7.5.2.4 Create FAR
 */
// clang-format on

#include "far_apply_user.h"
#include <bpf/libbpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_xdp_limits.h"
#include "utils/bpf_utils.hpp"

using namespace oai::utils::bpf;

//------------------------------------------------------------------------------
void FARProgram::ConfigureMaps(struct xdp_far_apply_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in FARProgram::ConfigureMaps");
    return;
  }

  bool ok = true;

  /* interfaces_maps.h -- owned by FARProgram, runtime-sized */
  ok &= ConfigureMapMaxEntries(
      skel->maps.upf_interface_map, "upf_interface_map",
      upf::GetMaxUpfInterfaces());

  ok &= ConfigureMapMaxEntries(
      skel->maps.redirect_interfaces_map, "redirect_interfaces_map",
      upf::GetMaxUpfRedirectInterfaces());

  /* arp_maps.h -- owned by FARProgram, runtime-sized */
  ok &= ConfigureMapMaxEntries(
      skel->maps.arp_table_map, "arp_table_map", upf::GetMaxArpEntries());

  /*
   * pipeline_maps.h and eth_pdu_maps.h maps are shared from the primary
   * entry program via bpf_map__reuse_fd before Setup() is called.
   * They must NOT be sized here -- they are already sized by their owner.
   */

  if (!ok) {
    Logger::upf_app().error(
        "One or more map configurations failed for FARProgram.");
    throw std::runtime_error("FARProgram map configuration failed");
  }

  /* rodata: 7 fields */
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
FARProgram::FARProgram() : BPFProgram() {
  Logger::upf_app().info("Initializing FAR XDP Program...");

  auto open_fn = [this]() -> xdp_far_apply_kern_c* {
    struct xdp_far_apply_kern_c* s = xdp_far_apply_kern_c__open();
    if (!s) {
      Logger::upf_app().error("Failed to open xdp_far_apply skeleton");
      return nullptr;
    }
    // Configure maps and rodata before skeleton is loaded
    this->ConfigureMaps(s);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = s;
    return s;
  };

  lifecycle_ = std::make_shared<FarProgramLifeCycle>(
      open_fn,
      /* load    */ xdp_far_apply_kern_c__load,
      /* attach  */ xdp_far_apply_kern_c__attach,
      /* destroy */ xdp_far_apply_kern_c__destroy);
}

//------------------------------------------------------------------------------
FARProgram::~FARProgram() {}

//------------------------------------------------------------------------------
void FARProgram::Setup() {
  /*
   * lifecycle_->open() is idempotent: if UPF_XDPProgram already called it
   * (to get the bpf_object for ShareMaps before loading), this returns the
   * cached skeleton with no side effects.
   */
  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
  Logger::upf_app().debug("FARProgram: loaded (no attach -- stage program)");
}

//------------------------------------------------------------------------------
void FARProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void FARProgram::InitializeMaps() {
  maps_    = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);
  auto get = [&](const char* name) {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };
  /* interfaces_maps.h -- owned */
  upf_interface_map_       = get("upf_interface_map");
  redirect_interfaces_map_ = get("redirect_interfaces_map");
  /* arp_maps.h -- owned */
  arp_table_map_ = get("arp_table_map");
  /*
   * pipeline_maps.h and eth_pdu_maps.h maps are present in this skeleton
   * (shared via reuse_fd) but are accessed via UPF_XDPProgram::GetMapByName()
   * delegation -- not wrapped here to avoid redundant BPFMap instances.
   */
}

//------------------------------------------------------------------------------
struct bpf_object* FARProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* FARProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* FARProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.far_apply : nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> FARProgram::GetMaps() const {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> FARProgram::GetUpfInterfaceMap() const {
  return upf_interface_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> FARProgram::GetRedirectInterfacesMap() const {
  return redirect_interfaces_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> FARProgram::GetArpTableMap() const {
  return arp_table_map_;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): See TODO in n3_entry_user.cpp -- GetMapCount() ownership.
 */
size_t FARProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}