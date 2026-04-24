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
 * Changes:     Boy Scout cleanup — changelog and @date normalised.
 *              No functional changes.
 * 3GPP Refs:   n/a — no PFCP §-refs in this file.
 */
// clang-format on

/**
 * @file BPFProgram.cpp
 * @brief Implementation of BPF program base class
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 */

#include "BPFProgram.h"
#include "logger.hpp"

// Initialize static ID counter starting from 1
uint32_t BPFProgram::id_counter_ = 1;

//------------------------------------------------------------------------------
BPFProgram::BPFProgram() : id_(id_counter_) {
  id_counter_++;
}

//------------------------------------------------------------------------------
BPFProgram::~BPFProgram() {
  Logger::upf_app().debug("BPF Program %u destroyed", id_);
}

//------------------------------------------------------------------------------
uint32_t BPFProgram::GetId() const {
  return id_;
}
