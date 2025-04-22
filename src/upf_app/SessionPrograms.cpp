#include "SessionPrograms.h"

/**************************************************************************************************/
SessionPrograms::SessionPrograms(
    struct next_rule_prog_index_key key,
    std::shared_ptr<FARProgram> pFARProgram)
    : mKey(key),
      mpFARProgram(pFARProgram),
      mPdnType(pdn_type_e::PDN_TYPE_E_IPV4) {}

SessionPrograms::SessionPrograms(
    struct next_rule_eth_prog_index_key key,
    std::shared_ptr<FARProgram> pFARProgram)
    : mKeyEth(key),
      mpFARProgram(pFARProgram),
      mPdnType(pdn_type_e::PDN_TYPE_E_ETHERNET) {}

/**************************************************************************************************/
SessionPrograms::~SessionPrograms() {
  mpFARProgram->tearDown();
}

/**************************************************************************************************/
struct next_rule_prog_index_key SessionPrograms::getKey() const {
  return mKey;
}

/**************************************************************************************************/
std::shared_ptr<FARProgram> SessionPrograms::getFARProgram() const {
  return mpFARProgram;
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