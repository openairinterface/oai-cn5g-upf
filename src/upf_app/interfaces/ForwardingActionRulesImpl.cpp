#include "ForwardingActionRulesImpl.h"
// // #include <utils/LogDefines.h>

ForwardingActionRulesImpl::ForwardingActionRulesImpl(pfcp_far_t_ &myFarStruct)
  : ForwardingActionRules()
{
  
  mFar = myFarStruct;
}

ForwardingActionRulesImpl::~ForwardingActionRulesImpl()
{
  
}

far_id_t_ ForwardingActionRulesImpl::getFARId()
{
  // Do not put LOG_FUNC() here.
  return mFar.far_id;
}

apply_action_t_ ForwardingActionRulesImpl::getApplyRules()
{
  
  return mFar.apply_action;
}

forwarding_parameters_t_ ForwardingActionRulesImpl::getForwardingParameters()
{
  
  return mFar.forwarding_parameters;
}

duplicating_parameters_t_ ForwardingActionRulesImpl::getDuplicatingParameters()
{
  
  return mFar.duplicating_parameters;
}

bar_id_t_ ForwardingActionRulesImpl::getBarId()
{
  
  return mFar.bar_id;
}

pfcp_far_t_ ForwardingActionRulesImpl::getData()
{
  
  return mFar;
}
