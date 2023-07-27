#include <Session.h>

/**************************************************************************************************/
Session::Session(u64 seid) : mSeid(seid) {}

/**************************************************************************************************/
Session::~Session() {}

/**************************************************************************************************/
void Session::addPDR(std::shared_ptr<PacketDetectionRule> pPdr) {
  mPDRs.push_back(pPdr);
  mPDRs.sort(Session::comparePDR);
}

/**************************************************************************************************/
void Session::addFAR(std::shared_ptr<ForwardingActionRule> pFar) {
  mFARs.push_back(pFar);
}

/**************************************************************************************************/
void Session::addPDR(std::shared_ptr<pfcp::pfcp_pdr> pPdr) {
  // mpSession->pdrs
}

/**************************************************************************************************/
void Session::addFAR(std::shared_ptr<pfcp::pfcp_far> pFAR) {}

/**************************************************************************************************/
bool Session::comparePDR(
    const std::shared_ptr<PacketDetectionRule>& first,
    const std::shared_ptr<PacketDetectionRule>& second) {
  return first->getPrecedence() < second->getPrecedence();
}

/**************************************************************************************************/
std::shared_ptr<PacketDetectionRule> Session::getHighestPrecedencePDR() {
  return *mPDRs.begin();
}

/**************************************************************************************************/
