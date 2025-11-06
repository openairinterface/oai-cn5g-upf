#include "SessionPrograms.h"

//---------------------------------------------------------------------------------------------------------------
SessionPrograms::SessionPrograms(
    // struct next_rule_prog_index_key key,
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
