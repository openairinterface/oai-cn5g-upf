/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SessionPrograms.h"

//---------------------------------------------------------------------------------------------------------------
SessionPrograms::SessionPrograms(
    std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram)
    : mpPFCP_Session_LookupProgram(pPFCP_Session_LookupProgram) {}

//---------------------------------------------------------------------------------------------------------------
SessionPrograms::~SessionPrograms() {
  mpPFCP_Session_LookupProgram->tearDown();
}

//---------------------------------------------------------------------------------------------------------------
std::shared_ptr<PFCP_Session_LookupProgram> SessionPrograms::getPFCPProgram()
    const {
  return mpPFCP_Session_LookupProgram;
}

/**************************************************************************************************/
pdn_type_e SessionPrograms::getPdnType() const {
  return mPdnType;
}
/**************************************************************************************************/
