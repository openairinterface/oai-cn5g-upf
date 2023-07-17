#include "PacketDetectionInformation.h"

/**************************************************************************************************/
PacketDetectionInformation::PacketDetectionInformation(
    u32 teid, u32 ueIpAddress, SourceInterface sourceInterface)
    : mTeid(teid),
      mUeIpAddress(ueIpAddress),
      mSourceInterface(sourceInterface) {}

/**************************************************************************************************/
PacketDetectionInformation::~PacketDetectionInformation() {}

/**************************************************************************************************/
u32 PacketDetectionInformation::getTeid() {
  return mTeid;
}

/**************************************************************************************************/
u32 PacketDetectionInformation::getUeIpAddress() {
  return mUeIpAddress;
}

/**************************************************************************************************/
u32 PacketDetectionInformation::getSourceInterface() {
  return mSourceInterface;
}

/**************************************************************************************************/
