/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SessionPrograms.h"

//---------------------------------------------------------------------------------------------------------------
SessionPrograms::SessionPrograms(
    // struct next_rule_prog_index_key key,
    std::shared_ptr<UPF_XDPProgram> pUPF_XDPProgram)
    : mpUPF_XDPProgram(pUPF_XDPProgram) {}

//---------------------------------------------------------------------------------------------------------------
SessionPrograms::~SessionPrograms() {
  mpUPF_XDPProgram->tearDown();
}

//---------------------------------------------------------------------------------------------------------------
std::shared_ptr<UPF_XDPProgram> SessionPrograms::getPFCPProgram() const {
  return mpUPF_XDPProgram;
}

/**************************************************************************************************/
pdn_type_e SessionPrograms::getPdnType() const {
  return mPdnType;
}
/**************************************************************************************************/
