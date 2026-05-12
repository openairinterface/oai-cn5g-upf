/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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
