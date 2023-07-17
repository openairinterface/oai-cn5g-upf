#include "RulesUtilitiesImpl.h"
#include <ForwardingActionRulesImpl.h>
#include <PacketDetectionRulesImpl.h>

/**************************************************************************************************/
RulesUtilitiesImpl::RulesUtilitiesImpl(/* args */) {}

/**************************************************************************************************/
RulesUtilitiesImpl::~RulesUtilitiesImpl() {}

/**************************************************************************************************/
void RulesUtilitiesImpl::copyFAR(
    pfcp_far_t_* pFarDestination, ForwardingActionRules* pFarSource) {
  *pFarDestination = pFarSource->getData();
}

/**************************************************************************************************/
std::shared_ptr<ForwardingActionRules> RulesUtilitiesImpl::createFAR(
    pfcp_far_t_* pFarSource) {
  return std::make_shared<ForwardingActionRulesImpl>(*pFarSource);
}

/**************************************************************************************************/
void RulesUtilitiesImpl::copyPDR(
    pfcp_pdr_t_* pPdrDestination, PacketDetectionRules* pPdrSource) {
  *pPdrDestination = pPdrSource->getData();
}

/**************************************************************************************************/
std::shared_ptr<PacketDetectionRules> RulesUtilitiesImpl::createPDR(
    pfcp_pdr_t_* pPdrSource) {
  return std::make_shared<PacketDetectionRulesImpl>(*pPdrSource);
}

/**************************************************************************************************/
