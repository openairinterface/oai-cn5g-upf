#include "SessionPrograms.h"

//---------------------------------------------------------------------------------------------------------------
SessionPrograms::SessionPrograms(
    struct next_rule_prog_index_key key,
    std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram)
    : mKey(key), mpPFCP_Session_LookupProgram(pPFCP_Session_LookupProgram) {}

//---------------------------------------------------------------------------------------------------------------
SessionPrograms::~SessionPrograms() {
  mpPFCP_Session_LookupProgram->tearDown();
}

//---------------------------------------------------------------------------------------------------------------
struct next_rule_prog_index_key SessionPrograms::getKey() const {
  return mKey;
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
struct next_rule_eth_prog_index_key SessionPrograms::getKeyEth() const {
  return mKeyEth;
}
/**************************************************************************************************/
