#include "PacketDetectionRulesImpl.h"

/**************************************************************************************************/
PacketDetectionRulesImpl::PacketDetectionRulesImpl(pfcp_pdr_t_& myPdr) {
  mPdr = myPdr;
}

/**************************************************************************************************/
PacketDetectionRulesImpl::~PacketDetectionRulesImpl() {}

/**************************************************************************************************/
teid_t_ PacketDetectionRulesImpl::getTeid() {
  return mPdr.pdi.fteid.teid;
}

/**************************************************************************************************/
pdr_id_t_ PacketDetectionRulesImpl::getPdrId() {
  return mPdr.pdr_id;
}

/**************************************************************************************************/
precedence_t_ PacketDetectionRulesImpl::getPrecedence() {
  return mPdr.precedence;
}

/**************************************************************************************************/
pdi_t_ PacketDetectionRulesImpl::getPdi() {
  return mPdr.pdi;
}

/**************************************************************************************************/
outer_header_removal_t_ PacketDetectionRulesImpl::getOuterHeaderRemoval() {
  return mPdr.outer_header_removal;
}

/**************************************************************************************************/
far_id_t_ PacketDetectionRulesImpl::getFarId() {
  return mPdr.far_id;
}

/**************************************************************************************************/
urr_id_t_ PacketDetectionRulesImpl::gerUrrId() {
  return mPdr.urr_id;
}

/**************************************************************************************************/
qer_id_t_ PacketDetectionRulesImpl::getQerId() {
  return mPdr.qer_id;
}

/**************************************************************************************************/
activate_predefined_rules_t_
PacketDetectionRulesImpl::getActivatePredefinedRules() {
  return mPdr.activate_predefined_rules;
}

/**************************************************************************************************/
pfcp_pdr_t_ PacketDetectionRulesImpl::getData() {
  return mPdr;
}

/**************************************************************************************************/
