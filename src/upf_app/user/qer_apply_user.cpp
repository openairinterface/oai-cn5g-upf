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
 * Changes:     New file. Follows n3_entry_user.cpp / session_lookup_ip_user.cpp
 *              pattern exactly (same as urr_apply_user.cpp / bar_apply_user.cpp).
 *              Constructor no longer opens the skeleton -- open is lazy.
 *              ConfigureMaps sets the 7 rodata fields from pipeline_maps.h;
 *              no ConfigureMapMaxEntries() calls because this program owns
 *              no maps -- all are shared from the primary via reuse_fd.
 *              Setup() = open (idempotent) + InitializeMaps + load.
 *              No attach() / link() -- stage program, reached via tail call.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §8.2.41 Gate Status
 */
// clang-format on

#include "qer_apply_user.h"
#include <bpf/libbpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_xdp_limits.h"
#include "utils/bpf_utils.hpp"

using namespace oai::utils::bpf;

//------------------------------------------------------------------------------
void QERProgram::ConfigureMaps(struct xdp_qer_apply_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in QERProgram::ConfigureMaps");
    return;
  }

  /*
   * xdp_qer_apply_kern.c owns NO maps.
   * All maps (rules_match_pdr_map etc.) come from pipeline_maps.h and are
   * shared from the primary entry program via bpf_map__reuse_fd before
   * Setup() is called. No ConfigureMapMaxEntries() calls needed.
   *
   * pipeline_maps.h declares 7 rodata fields -- set them all so the bounds
   * checks in the BPF program use the correct runtime values.
   */
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
QERProgram::QERProgram() : BPFProgram() {
  Logger::upf_app().debug("Initializing QER XDP Program ...");

  auto open_fn = [this]() -> xdp_qer_apply_kern_c* {
    struct xdp_qer_apply_kern_c* s = xdp_qer_apply_kern_c__open();
    if (!s) {
      Logger::upf_app().error("Failed to open xdp_qer_apply skeleton");
      return nullptr;
    }
    // Configure rodata before skeleton is loaded
    this->ConfigureMaps(s);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = s;
    return s;
  };

  lifecycle_ = std::make_shared<QerProgramLifeCycle>(
      open_fn,
      /* load    */ xdp_qer_apply_kern_c__load,
      /* attach  */ xdp_qer_apply_kern_c__attach,
      /* destroy */ xdp_qer_apply_kern_c__destroy, "QERProgram");
}

//------------------------------------------------------------------------------
void QERProgram::Setup() {
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
void QERProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void QERProgram::InitializeMaps() {
  /*
   * All maps in this skeleton are shared from the primary entry program
   * via bpf_map__reuse_fd. We still wrap the skeleton so GetMapCount()
   * can report the number of map slots (even though all FDs are reused).
   */
  maps_ = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);
}

//------------------------------------------------------------------------------
struct bpf_object* QERProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* QERProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* QERProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.qer_apply : nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> QERProgram::GetMaps() const {
  return maps_;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): See TODO in n3_entry_user.cpp -- GetMapCount() ownership.
 */
size_t QERProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}
