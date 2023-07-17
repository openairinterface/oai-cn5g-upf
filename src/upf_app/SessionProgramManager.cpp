#include "SessionProgramManager.h"
#include <far_ebpf_xdp_prgrm_user.h>
#include <pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.h>
#include "SessionPrograms.h"
#include <pfcp_session_lookup_ebpf_xdp_prgrm_user.h>
#include <UserPlaneComponent.h>
#include <net/if.h>  // if_nametoindex
#include <next_prog_rule_key.h>
#include <observer/OnStateChangeSessionProgramObserver.h>
#include <pfcp/pfcp_far.h>
#include <spdlog/fmt/ostr.h>
#include <types.h>
#include <wrappers/BPFMap.hpp>
#include "logger.hpp"
#include "NextHopFinder.hpp"

#include <arpa/inet.h>

#define EMPTY_SLOT -1l

/*****************************************************************************************************************/
int is_little_endian() {
  u32 value = 1;
  u8* byte  = (u8*) &value;
  return (*byte == 1);
}

/*****************************************************************************************************************/
std::ostream& operator<<(
    std::ostream& Str, struct next_rule_prog_index_key const& v) {
  Str << "TEID: " << v.teid << " SOURCE INTERFACE: " << v.source_value
      << "IPv4 ADDRESS: " << v.ipv4_address;
  return Str;
}

/*****************************************************************************************************************/
SessionProgramManager::~SessionProgramManager() {
  removeAll();
}

/*****************************************************************************************************************/
SessionProgramManager& SessionProgramManager::getInstance() {
  static SessionProgramManager sInstance;
  return sInstance;
}

/*****************************************************************************************************************/
void SessionProgramManager::setTeidSessionMap(
    std::shared_ptr<BPFMap> pProgramsMaps) {
  mpTeidSessionMap = pProgramsMaps;
}

/*****************************************************************************************************************/
void SessionProgramManager::createPipeline(
    uint32_t seid, uint32_t teid, uint8_t sourceInterface, uint32_t ueIpAddress,
    std::shared_ptr<pfcp::pfcp_far> pFar) {
  struct next_rule_prog_index_key key;
  u32 id;
  s32 fd;

  __builtin_memset(&key, 0, sizeof(struct next_rule_prog_index_key));

  if (is_little_endian()) {
    key.teid         = htobe32(teid);
    key.ipv4_address = htole32(ueIpAddress);
  } else {
    key.teid         = htole32(teid);
    key.ipv4_address = ueIpAddress;
  }

  key.source_value = sourceInterface;

  Logger::upf_app().debug("Instantiate a new FARProgram");
  std::shared_ptr<FARProgram> pFARProgram = std::make_shared<FARProgram>();
  pFARProgram->setup();

  Logger::upf_app().debug("Store FARProgram index in the UPFProgram");
  auto pPFCP_Session_LookupProgram =
      UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();
  id = pFARProgram->getId();
  fd = pFARProgram->getFd();

  // TODO: Get the nextProgRule index from a pool of values.
  pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->update(
      key, id, BPF_ANY);
  pPFCP_Session_LookupProgram->getNextProgRuleMap()->update(id, fd, BPF_ANY);

  Logger::upf_app().debug("Store FAR in the FAR program");
  uint8_t index = 0;

  // TODO: Create a method to encapuslate.
  pfcp_far_t_ far;
  // FAR ID
  far.far_id.far_id = pFar->far_id.far_id;
  // FORWARDING PARAMETERS INTERFACE VALUE
  far.forwarding_parameters.destination_interface.interface_value =
      pFar->forwarding_parameters.second.destination_interface.second
          .interface_value;
  // FORWARDING PARAMETERS TEID
  far.forwarding_parameters.outer_header_creation.teid =
      pFar->forwarding_parameters.second.outer_header_creation.second.teid;
  // FORWARDING PARAMETERS PORT NUMBER
  far.forwarding_parameters.outer_header_creation.port_number =
      pFar->forwarding_parameters.second.outer_header_creation.second
          .port_number;
  // FORWARDING PARAMETERS HEADER CREATION
  far.forwarding_parameters.outer_header_creation
      .outer_header_creation_description =
      pFar->forwarding_parameters.second.outer_header_creation.second
          .outer_header_creation_description;
  // FORWARDING PARAMETERS SOURCE IP ADDRESS
  far.forwarding_parameters.outer_header_creation.ipv4_address.s_addr =
      pFar->forwarding_parameters.second.outer_header_creation.second
          .ipv4_address.s_addr;
  // FORWARDING PARAMETERS ACTIONS
  memcpy(&far.apply_action, &pFar->apply_action, sizeof(apply_action_t_));

  pFARProgram->getFARMap()->update(index, far, BPF_ANY);

  // Map the pipeline deployed to the seid. The seid will be used to detroyed
  // it.
  mSessionProgramsMap[seid] =
      std::make_shared<SessionPrograms>(key, pFARProgram);

  // NextHopFinder finder;
  // uint32_t ipnexthop = finder.retrieveNextHopIP(ueIpAddress);

  // auto pMacAddress = finder.retrieveNextHopMAC(ipnexthop);
  // ipnexthop        = (is_little_endian()) ? htonl(ipnexthop) : ipnexthop;
  // pFARProgram->getArpTableMap()->update(
  //     ipnexthop, pMacAddress->ether_addr_octet, BPF_ANY);
}

/*****************************************************************************************************************/
void SessionProgramManager::updatePipeline(
    uint32_t seid, uint32_t teid, uint8_t sourceInterface,
    uint32_t gNBIpAddress, std::shared_ptr<pfcp::pfcp_far> pFar) {
  struct next_rule_prog_index_key key;
  u32 id;
  s32 fd;

  __builtin_memset(&key, 0, sizeof(struct next_rule_prog_index_key));

  if (is_little_endian()) {
    key.teid         = htobe32(teid);
    key.ipv4_address = htobe32(gNBIpAddress);
  } else {
    key.teid         = htole32(teid);
    key.ipv4_address = gNBIpAddress;
  }
  Logger::upf_app().debug("gnb1: %d", htobe32(gNBIpAddress));
  Logger::upf_app().debug("gnb2: %d", htole32(gNBIpAddress));
  Logger::upf_app().debug("gnb3: %d", gNBIpAddress);
  key.source_value = sourceInterface;

  Logger::upf_app().debug("Instantiate a new FARProgram");
  std::shared_ptr<FARProgram> pFARProgram = std::make_shared<FARProgram>();
  pFARProgram->setup();

  Logger::upf_app().debug("Store FARProgram index in the UPFProgram");
  auto pPFCP_Session_LookupProgram =
      UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();
  id = pFARProgram->getId();
  fd = pFARProgram->getFd();

  // TODO: Get the nextProgRule index from a pool of values.
  pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->update(
      key, id, BPF_ANY);
  pPFCP_Session_LookupProgram->getNextProgRuleMap()->update(id, fd, BPF_ANY);

  Logger::upf_app().debug("Store FAR in the FAR program");
  uint8_t index = 0;

  // TODO: Create a method to encapuslate.
  pfcp_far_t_ far;
  // FAR ID
  far.far_id.far_id = pFar->far_id.far_id;
  // FORWARDING PARAMETERS INTERFACE VALUE
  far.forwarding_parameters.destination_interface.interface_value =
      pFar->forwarding_parameters.second.destination_interface.second
          .interface_value;
  // FORWARDING PARAMETERS TEID
  far.forwarding_parameters.outer_header_creation.teid =
      pFar->forwarding_parameters.second.outer_header_creation.second.teid;
  // FORWARDING PARAMETERS PORT NUMBER
  far.forwarding_parameters.outer_header_creation.port_number =
      pFar->forwarding_parameters.second.outer_header_creation.second
          .port_number;
  // FORWARDING PARAMETERS HEADER CREATION
  far.forwarding_parameters.outer_header_creation
      .outer_header_creation_description =
      pFar->forwarding_parameters.second.outer_header_creation.second
          .outer_header_creation_description;
  // FORWARDING PARAMETERS SOURCE IP ADDRESS
  far.forwarding_parameters.outer_header_creation.ipv4_address.s_addr =
      pFar->forwarding_parameters.second.outer_header_creation.second
          .ipv4_address.s_addr;
  // FORWARDING PARAMETERS ACTIONS
  memcpy(&far.apply_action, &pFar->apply_action, sizeof(apply_action_t_));

  pFARProgram->getFARMap()->update(index, far, BPF_ANY);

  // Map the pipeline deployed to the seid. The seid will be used to detroyed
  // it.
  mSessionProgramsMap[seid] =
      std::make_shared<SessionPrograms>(key, pFARProgram);

  NextHopFinder finder;
  // uint32_t ipnexthop = finder.retrieveNextHopIP(gNBIpAddress);

  // auto pMacAddress = finder.retrieveNextHopMAC(ipnexthop);
  auto pMacAddress = finder.retrieveNextHopMAC(gNBIpAddress);
  uint32_t ipnexthop =
      (is_little_endian()) ? htonl(gNBIpAddress) : gNBIpAddress;
  pFARProgram->getArpTableMap()->update(
      ipnexthop, pMacAddress->ether_addr_octet, BPF_ANY);
}

/*****************************************************************************************************************/
void SessionProgramManager::removePipeline(uint32_t seid) {
  Logger::upf_app().debug("Remove FARProgram index from UPFProgram map");
  auto it = mSessionProgramsMap.find(seid);
  if (it == mSessionProgramsMap.end()) {
    Logger::upf_app().error(
        "Session %d Does Not Exist. It Cannot be Removed", seid);
    throw std::runtime_error("Session does Not Exist. It Cannot be Removed");
  }

  Logger::upf_app().debug(
      "Delete the SessionPrograms object. It will release the pipeline");
  // The key represent the pointer to the pipeline related to the session.
  auto key = it->second->getKey();
  it->second.reset();
  mSessionProgramsMap.erase(seid);

  Logger::upf_app().debug("Clean PDU Session from the entry program's map");
  auto pPFCP_Session_LookupProgram =
      UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();
  pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->remove(key);
}

/*****************************************************************************************************************/
void SessionProgramManager::create(uint32_t seid) {
  // Check if there is a key with seid value.
  // TODO: Check if can be abstract the programMap.

  if (mSessionProgramMap.find(seid) != mSessionProgramMap.end()) {
    Logger::upf_app().error(
        "PDU Session {} Already Exists. Cannot Create a New eBPF Program with "
        "the same "
        "key",
        seid);
    throw std::runtime_error(
        "Cannot Create a New eBPF program with Key (seid)");
  }

  // Instantiate a new PFCP_Session_PDR_LookupProgram
  auto udpInterface = UserPlaneComponent::getInstance().getUDPInterface();
  auto gtpInterface = UserPlaneComponent::getInstance().getGTPInterface();
  std::shared_ptr<PFCP_Session_PDR_LookupProgram>
      pPFCP_Session_PDR_LookupProgram =
          std::make_shared<PFCP_Session_PDR_LookupProgram>(
              gtpInterface, udpInterface);
  pPFCP_Session_PDR_LookupProgram->setup();

  // Initialize key egress interface map.
  uint32_t udpInterfaceIndex = if_nametoindex(udpInterface.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(gtpInterface.c_str());

  uint32_t uplinkId   = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlinkId = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  pPFCP_Session_PDR_LookupProgram->getEgressInterfaceMap()->update(
      uplinkId, udpInterfaceIndex, BPF_ANY);
  pPFCP_Session_PDR_LookupProgram->getEgressInterfaceMap()->update(
      downlinkId, gtpInterfaceIndex, BPF_ANY);

  // Update the PFCP_Session_PDR_LookupProgram map.
  mSessionProgramMap.insert(
      std::pair<uint32_t, std::shared_ptr<PFCP_Session_PDR_LookupProgram>>(
          seid, pPFCP_Session_PDR_LookupProgram));
}

/*****************************************************************************************************************/
void SessionProgramManager::remove(uint32_t seid) {
  auto sessionProgram = findSessionProgram(seid);
  if (!sessionProgram) {
    Logger::upf_app().error(
        "The PDU session %d does not exist. Cannot be removed", seid);
    throw std::runtime_error("The session does not exist. Cannot be removed");
  }
  sessionProgram->tearDown();
  mSessionProgramMap.erase(seid);
}

/*****************************************************************************************************************/
void SessionProgramManager::removeAll() {
  for (auto pair : mSessionProgramMap) {
    pair.second->tearDown();

    // Notify observer that a PFCP_Session_PDR_LookupProgram was removed.
    mpOnNewSessionProgramObserver->onDestroySessionProgram(pair.first);
  }
  mSessionProgramMap.clear();
}

/*****************************************************************************************************************/
void SessionProgramManager::setOnNewSessionObserver(
    OnStateChangeSessionProgramObserver* pObserver) {
  mpOnNewSessionProgramObserver = pObserver;
}

/*****************************************************************************************************************/
std::shared_ptr<PFCP_Session_PDR_LookupProgram>
SessionProgramManager::findSessionProgram(uint32_t seid) {
  std::shared_ptr<PFCP_Session_PDR_LookupProgram>
      pPFCP_Session_PDR_LookupProgram;

  auto it = mSessionProgramMap.find(seid);
  if (it != mSessionProgramMap.end()) {
    pPFCP_Session_PDR_LookupProgram = it->second;
  }

  return pPFCP_Session_PDR_LookupProgram;
}

/*****************************************************************************************************************/
std::shared_ptr<SessionPrograms> SessionProgramManager::findSessionPrograms(
    uint32_t seid) {
  std::shared_ptr<SessionPrograms> pSessionPrograms;

  auto it = mSessionProgramsMap.find(seid);
  if (it != mSessionProgramsMap.end()) {
    pSessionPrograms = it->second;
  }

  return pSessionPrograms;
}

/*****************************************************************************************************************/
SessionProgramManager::SessionProgramManager() {
  for (auto& item : mProgramArray) {
    item = EMPTY_SLOT;
  }
}

/*****************************************************************************************************************/
int32_t SessionProgramManager::getEmptySlot() {
  auto it = std::find(mProgramArray.begin(), mProgramArray.end(), EMPTY_SLOT);
  if (it != mProgramArray.end()) {
    auto index = it - mProgramArray.begin();
    Logger::upf_app().error("Element with index %d is empty", index);
    return index;
  } else {
    Logger::upf_app().error("No Space Available");
    throw std::runtime_error("No Space Available");
  }
}
