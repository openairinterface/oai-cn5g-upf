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
 * Changes:     Own lifecycle_ (BPFProgram pattern). No unique maps.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 ss8.2.22-26 FAR IE
 */
// clang-format on

#include "far_apply_user.h"
#include <stdexcept>
#include "logger.hpp"

//------------------------------------------------------------------------------
FARProgram::FARProgram() : BPFProgram() {
  auto open_fn = [this]() -> xdp_far_apply_kern_c* {
    auto* s = xdp_far_apply_kern_c__open();
    if (!s) throw std::runtime_error("Failed to open xdp_far_apply skeleton");
    return s;
  };
  lifecycle_ = std::make_shared<FarProgramLifeCycle>(
      open_fn, xdp_far_apply_kern_c__load, xdp_far_apply_kern_c__attach,
      xdp_far_apply_kern_c__destroy);
  skeleton_ = lifecycle_->open();
  Logger::upf_app().debug("FARProgram: skeleton opened");
}

//------------------------------------------------------------------------------
FARProgram::~FARProgram() {}

//------------------------------------------------------------------------------
void FARProgram::Load() {
  lifecycle_->load();
  Logger::upf_app().debug("FARProgram: skeleton loaded");
}

//------------------------------------------------------------------------------
struct bpf_object* FARProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* FARProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.far_apply : nullptr;
}