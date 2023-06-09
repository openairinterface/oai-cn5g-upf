#include "SessionProgramManager.h"
#include <far_ebpf_xdp_prgrm_user.h>
#include <pfcp_session_lookup_ebpf_xdp_prgrm_user.h>
#include <SessionPrograms.h>
#include <pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.h>
#include <UserPlaneComponent.h>
#include <net/if.h>  // if_nametoindex
#include <next_prog_rule_key.h>
#include <observer/OnStateChangeSessionProgramObserver.h>
#include <pfcp/pfcp_far.h>
#include <spdlog/fmt/ostr.h>
#include <types.h>
// // #include <utils/LogDefines.h>
#include <wrappers/BPFMap.hpp>
#include "logger.hpp"

#include <arpa/inet.h>

#define EMPTY_SLOT -1l

//  TODO: Encapsulate in order file.
// Custom format for next_rule_prog_index_key.

/*****************************************************************************************************************/
u32 litToBigEndian(u32 x) {
  return (
      ((x << 24) & 0xff000000) | ((x << 8) & 0x00ff0000) |
      ((x >> 24) & 0x000000ff) | ((x >> 8) & 0x0000ff00));
};

/*****************************************************************************************************************/
u32 bigToLitEndian(u32 x) {
  return (
      ((x >> 24) & 0x000000ff) | ((x >> 8) & 0x0000ff00) |
      ((x << 8) & 0x00ff0000) | ((x << 24) & 0xff000000));
};

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
  struct in_addr ip_addr;
  u32 id;
  s32 fd;

  __builtin_memset(&key, 0, sizeof(struct next_rule_prog_index_key));

  key = {
      .teid         = teid,
      .source_value = sourceInterface,
      .ipv4_address = ueIpAddress};
  // key = {.teid = litToBigEndian(teid), .source_value = sourceInterface,
  // .ipv4_address = litToBigEndian(ueIpAddress)};

  ip_addr.s_addr = ueIpAddress;
  // LOG_DBG("TEID: {}, Source Interface: {}, UE IP: {}", htonl(teid),
  // sourceInterface, inet_ntoa(ip_addr));
  // ToDo Verify ip to string conversion
  // Logger::upf_app().debug("TEID: %d, Source Interface: %d, UE IP: {}",
  // htonl(teid), sourceInterface, inet_ntoa(ip_addr));

  // LOG_DBG("Instantiate a new FARProgram");
  Logger::upf_app().debug("Instantiate a new FARProgram");
  std::shared_ptr<FARProgram> pFARProgram = std::make_shared<FARProgram>();
  pFARProgram->setup();

  // LOG_DBG("Store FARProgram index in the UPFProgram");
  Logger::upf_app().debug("Store FARProgram index in the UPFProgram");
  auto pUPFProgram = UserPlaneComponent::getInstance().getUPFProgram();
  id               = pFARProgram->getId();
  fd               = pFARProgram->getFd();

  // TODO: Get the nextProgRule index from a pool of values.
  pUPFProgram->getNextProgRuleIndexMap()->update(key, id, BPF_ANY);
  pUPFProgram->getNextProgRuleMap()->update(id, fd, BPF_ANY);

  // LOG_DBG("Store FAR in the FAR program");
  Logger::upf_app().debug("Store FAR in the FAR program");
  uint8_t index = 0;
  // TODO: Create a method to encapuslate.
  /*
  pfcp_far_t_ far = {// FAR ID.
                     .far_id.far_id = pFar->far_id.far_id,
                     //  Fwd - Destination interface value
                     .forwarding_parameters.destination_interface.interface_value
  =
                         pFar->forwarding_parameters.second.destination_interface.second.interface_value,
                     //  Fwd - teid
                     .forwarding_parameters.outer_header_creation.teid =
                         pFar->forwarding_parameters.second.outer_header_creation.second.teid,
                     //  Fwd - port
                     .forwarding_parameters.outer_header_creation.port_number =
                         pFar->forwarding_parameters.second.outer_header_creation.second.port_number,
                     //  Fwd - creation interface
                     .forwarding_parameters.outer_header_creation.outer_header_creation_description
  =
                         pFar->forwarding_parameters.second.outer_header_creation.second.outer_header_creation_description,
                     // Fwd - ipv4
                     .forwarding_parameters.outer_header_creation.ipv4_address.s_addr
  =
                         pFar->forwarding_parameters.second.outer_header_creation.second.ipv4_address.s_addr};
  */
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
}

/*****************************************************************************************************************/
void SessionProgramManager::removePipeline(uint32_t seid) {
  // LOG_DBG("Remove FARProgram index from UPFProgram map");
  Logger::upf_app().debug("Remove FARProgram index from UPFProgram map");
  auto it = mSessionProgramsMap.find(seid);
  if (it == mSessionProgramsMap.end()) {
    // LOG_ERROR("The PDU Session {} does not exist. Cannot be removed", seid);
    Logger::upf_app().error(
        "The PDU Session %d does not exist. Cannot be removed", seid);
    throw std::runtime_error("The session does not exist. Cannot be removed");
  }

  // LOG_DBG("Delete the SessionPrograms object. It will release the pipeline");
  Logger::upf_app().debug(
      "Delete the SessionPrograms object. It will release the pipeline");
  // The key represent the pointer to the pipeline related to the session.
  auto key = it->second->getKey();
  it->second.reset();
  mSessionProgramsMap.erase(seid);

  // LOG_DBG("Clean PDU Session from the entry program's map");
  Logger::upf_app().debug("Clean PDU Session from the entry program's map");
  auto pUPFProgram = UserPlaneComponent::getInstance().getUPFProgram();
  pUPFProgram->getNextProgRuleIndexMap()->remove(key);
}

/*****************************************************************************************************************/
void SessionProgramManager::create(uint32_t seid) {
  // Check if there is a key with seid value.
  // TODO: Check if can be abstract the programMap.

  if (mSessionProgramMap.find(seid) != mSessionProgramMap.end()) {
    // LOG_ERROR("PDU Session {} already exists. Cannot create a new program
    // with this key", seid);
    Logger::upf_app().error(
        "PDU Session {} already exists. Cannot create a new program with this "
        "key",
        seid);
    throw std::runtime_error("Cannot create a new program with key (seid)");
  }

  // Instantiate a new SessionProgram
  auto udpInterface = UserPlaneComponent::getInstance().getUDPInterface();
  auto gtpInterface = UserPlaneComponent::getInstance().getGTPInterface();
  std::shared_ptr<SessionProgram> pSessionProgram =
      std::make_shared<SessionProgram>(gtpInterface, udpInterface);
  pSessionProgram->setup();

  // Initialize key egress interface map.
  uint32_t udpInterfaceIndex = if_nametoindex(udpInterface.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(gtpInterface.c_str());

  uint32_t uplinkId   = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlinkId = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  pSessionProgram->getEgressInterfaceMap()->update(
      uplinkId, udpInterfaceIndex, BPF_ANY);
  pSessionProgram->getEgressInterfaceMap()->update(
      downlinkId, gtpInterfaceIndex, BPF_ANY);

  // Update the SessionProgram map.
  mSessionProgramMap.insert(
      std::pair<uint32_t, std::shared_ptr<SessionProgram>>(
          seid, pSessionProgram));
}

/*****************************************************************************************************************/
void SessionProgramManager::remove(uint32_t seid) {
  auto sessionProgram = findSessionProgram(seid);
  if (!sessionProgram) {
    // LOG_ERROR("The PDU session {} does not exist. Cannot be removed", seid);
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

    // Notify observer that a SessionProgram was removed.
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
std::shared_ptr<SessionProgram> SessionProgramManager::findSessionProgram(
    uint32_t seid) {
  std::shared_ptr<SessionProgram> pSessionProgram;

  auto it = mSessionProgramMap.find(seid);
  if (it != mSessionProgramMap.end()) {
    pSessionProgram = it->second;
  }

  return pSessionProgram;
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
    // LOG_DBG("Element with index {} is empty", index);
    Logger::upf_app().error("Element with index %d is empty", index);
    return index;
  } else {
    // LOG_ERROR("No space available");
    Logger::upf_app().error("No space available");
    throw std::runtime_error("No space available");
  }
}
/*****************************************************************************************************************/