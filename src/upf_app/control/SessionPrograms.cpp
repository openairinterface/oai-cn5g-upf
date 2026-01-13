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

/**
 * @file SessionPrograms.cpp
 * @brief Session Programs Container Implementation
 * @author OpenAirInterface
 * @date 2025
 */

#include "SessionPrograms.h"
#include <upf_xdp_user.h>

//------------------------------------------------------------------------------
SessionPrograms::SessionPrograms(
    std::shared_ptr<UPF_XDPProgram> upf_xdp_program)
    : upf_xdp_program_(upf_xdp_program) {}

//------------------------------------------------------------------------------
SessionPrograms::~SessionPrograms() {
  if (upf_xdp_program_) {
    upf_xdp_program_->TearDown();
  }
}

//------------------------------------------------------------------------------
std::shared_ptr<UPF_XDPProgram> SessionPrograms::GetPFCPProgram() const {
  return upf_xdp_program_;
}
