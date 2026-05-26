/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file BPFProgram.cpp
 * @brief Implementation of BPF program base class
 */

#include "BPFProgram.h"
#include "logger.hpp"

// Initialize static ID counter starting from 1
uint32_t BPFProgram::id_counter_ = 1;

//------------------------------------------------------------------------------
BPFProgram::BPFProgram() : id_(id_counter_) {
  id_counter_++;
  Logger::upf_app().info("BPF Program %u created", id_);
}

//------------------------------------------------------------------------------
BPFProgram::~BPFProgram() {
  Logger::upf_app().debug("BPF Program %u destroyed", id_);
}

//------------------------------------------------------------------------------
uint32_t BPFProgram::GetId() const {
  return id_;
}
