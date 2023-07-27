#include "PacketDetectionRule.h"

/**************************************************************************************************/
PacketDetectionRule::PacketDetectionRule(
    u32 precedence, std::shared_ptr<PacketDetectionInformation> pdi, u32 farId)
    : mPrecedence(precedence), mPDI(pdi), mFarId(farId) {}

/**************************************************************************************************/
PacketDetectionRule::~PacketDetectionRule() {}

/**************************************************************************************************/
u32 PacketDetectionRule::getPrecedence() {
  return mPrecedence;
}

/**************************************************************************************************/
std::shared_ptr<PacketDetectionInformation> PacketDetectionRule::getPDI() {
  return mPDI;
}

/**************************************************************************************************/
u32 PacketDetectionRule::getFarId() {
  return mFarId;
}

/**************************************************************************************************/
