#include "SessionPrograms.h"

/**************************************************************************************************/
SessionPrograms::SessionPrograms(
    struct next_rule_prog_index_key key,
    std::shared_ptr<FARProgram> pFARProgram)
    : mKey(key), mpFARProgram(pFARProgram) {}

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
