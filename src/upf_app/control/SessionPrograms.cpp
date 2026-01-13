/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file SessionPrograms.cpp
 * @brief Session Programs Container Implementation
 */

#include "SessionPrograms.h"
#include <upf_xdp_user.h>
#include <qer_tc_user.h>
//------------------------------------------------------------------------------
SessionPrograms::SessionPrograms(
    std::shared_ptr<UPF_XDPProgram> upf_xdp_program)
    : upf_xdp_program_(upf_xdp_program) {}

//------------------------------------------------------------------------------
std::shared_ptr<UPF_XDPProgram> SessionPrograms::GetPFCPProgram() const {
  return upf_xdp_program_;
}

//------------------------------------------------------------------------------
void SessionPrograms::SetQERProgram(std::shared_ptr<QERProgram> qer_program) {
  qer_program_ = qer_program;
}

//------------------------------------------------------------------------------
std::shared_ptr<QERProgram> SessionPrograms::GetQERProgram() const {
  return qer_program_;
}
//------------------------------------------------------------------------------

SessionPrograms::~SessionPrograms() {
  // Tear down QER program first
  if (qer_program_) {
    qer_program_->TearDown();
    qer_program_.reset();
  }

  // Then XDP program
  if (upf_xdp_program_) {
    upf_xdp_program_->TearDown();
  }
}
