#include "RulesUtilitiesImpl.h"
// // #include <utils/LogDefines.h>
#include <ForwardingActionRulesImpl.h>
#include <PacketDetectionRulesImpl.h>

RulesUtilitiesImpl::RulesUtilitiesImpl(/* args */) {}

RulesUtilitiesImpl::~RulesUtilitiesImpl() {}

void RulesUtilitiesImpl::copyFAR(
    pfcp_far_t_* pFarDestination, ForwardingActionRules* pFarSource) {
  // Copy the contents. In this case, the Impl receives the same struct.
  // PS: If the far structs is different, call set methods here.
  *pFarDestination = pFarSource->getData();
}

std::shared_ptr<ForwardingActionRules> RulesUtilitiesImpl::createFAR(
    pfcp_far_t_* pFarSource) {
  // Copy the contents. In this case, the Impl receives the same struct.
  // PS: If the far structs is different, call set methods here.
  return std::make_shared<ForwardingActionRulesImpl>(*pFarSource);
}

void RulesUtilitiesImpl::copyPDR(
    pfcp_pdr_t_* pPdrDestination, PacketDetectionRules* pPdrSource) {
  // Copy the contents. In this case, the Impl receives the same struct.
  // PS: If the far structs is different, call set methods here.
  *pPdrDestination = pPdrSource->getData();
}

std::shared_ptr<PacketDetectionRules> RulesUtilitiesImpl::createPDR(
    pfcp_pdr_t_* pPdrSource) {
  // Copy the contents. In this case, the Impl receives the same struct.
  // PS: If the far structs is different, call set methods here.
  return std::make_shared<PacketDetectionRulesImpl>(*pPdrSource);
}
