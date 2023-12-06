#include "SessionProgramManager.h"
#include <far_ebpf_xdp_prgrm_user.h>
#include <pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.h>
#include "SessionPrograms.h"
#include <pfcp_session_lookup_ebpf_xdp_prgrm_user.h>
#include <UserPlaneComponent.h>
#include <net/if.h>  // if_nametoindex

#include <observer/OnStateChangeSessionProgramObserver.h>
// #include <pfcp/pfcp_far.h>
#include <spdlog/fmt/ostr.h>
#include <types.h>
#include <wrappers/BPFMap.hpp>
#include "logger.hpp"
#include "NextHopFinder.hpp"
#include <errno.h>
#include <arpa/inet.h>
//#include <traffic_classification.h>
// #include <ue_teid_qfi_matching.h>
#include <session_mapping.h>
#include <arp_table_maps.h>
#include "upf_config.hpp"
#include <thread>

using namespace oai::config;
extern upf_config upf_cfg;

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
SessionProgramManager::SessionProgramManager() {
  for (auto& item : mProgramArray) {
    item = EMPTY_SLOT;
  }
  farPrograms = std::make_shared<std::vector<farprograms>>();
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
void SessionProgramManager::addFarProgram(
    uint32_t seid, std::shared_ptr<FARProgram> pFARProgram) {
  // Create a new 'farprograms' object
  farprograms farprogam;
  __builtin_memset(&farprogam, 0, sizeof(farprograms));
  farprogam.seid        = seid;
  farprogam.pFARProgram = pFARProgram;

  farPrograms->push_back(farprogam);
}

/*****************************************************************************************************************/
uint32_t SessionProgramManager::getRemoteIP(uint32_t upfIP, uint32_t remoteIP) {
  NextHopFinder finder;
  uint32_t ipnexthop = 0;
  if (not finder.sameSubnet(upfIP, remoteIP)) {
    Logger::upf_app().debug("Not in the same subnet");
    ipnexthop = finder.retrieveNextHopIP(remoteIP);
  } else {
    Logger::upf_app().debug("The same subnet");
    ipnexthop = remoteIP;
  }
  return ipnexthop;
}

/*****************************************************************************************************************/
pfcp_far_t_ SessionProgramManager::createFar(
    std::shared_ptr<pfcp::pfcp_far> pFar) {
  pfcp_far_t_ far;

  far.far_id.far_id = pFar->far_id.far_id;

  far.forwarding_parameters.destination_interface.interface_value =
      pFar->forwarding_parameters.second.destination_interface.second
          .interface_value;

  far.forwarding_parameters.outer_header_creation.teid =
      pFar->forwarding_parameters.second.outer_header_creation.second.teid;

  far.forwarding_parameters.outer_header_creation.port_number =
      pFar->forwarding_parameters.second.outer_header_creation.second
          .port_number;

  far.forwarding_parameters.outer_header_creation
      .outer_header_creation_description =
      pFar->forwarding_parameters.second.outer_header_creation.second
          .outer_header_creation_description;

  far.forwarding_parameters.outer_header_creation.ipv4_address.s_addr =
      pFar->forwarding_parameters.second.outer_header_creation.second
          .ipv4_address.s_addr;

  memcpy(&far.apply_action, &pFar->apply_action, sizeof(apply_action_t_));

  return far;
}

/*****************************************************************************************************************/
// Helper function to initialize the key for the FARProgram
void SessionProgramManager::initializeNextRuleProgIndexKey(
    next_rule_prog_index_key& key, uint32_t teid, uint32_t ueIpAddress,
    uint8_t sourceInterface) {
  __builtin_memset(&key, 0, sizeof(struct next_rule_prog_index_key));

  if (is_little_endian()) {
    key.teid         = htobe32(teid);
    key.ipv4_address = htole32(ueIpAddress);
  } else {
    key.teid         = htole32(teid);
    key.ipv4_address = ueIpAddress;
  }

  key.source_value = sourceInterface;
}

/*****************************************************************************************************************/
// Helper function to store the FARProgram index in the LookupProgram
// std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram
void SessionProgramManager::storeFarProgramIndexInNextProgRuleIndexMap(
    std::shared_ptr<FARProgram> pFARProgram,
    const next_rule_prog_index_key& key,
    std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram) {
  // auto pPFCP_Session_LookupProgram =
  //     UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();
  u32 id = pFARProgram->getId();
  s32 fd = pFARProgram->getFd();

  pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->update(
      key, id, BPF_ANY);
  pPFCP_Session_LookupProgram->getNextProgRuleMap()->update(id, fd, BPF_ANY);
}

/*****************************************************************************************************************/
// Helper function to store Session mapping
void SessionProgramManager::storeSessionMappingMap(
    std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
    uint32_t ue_ip_address, uint32_t teid_dl) {
  uint32_t key;

  if (is_little_endian()) {
    key     = htole32(ue_ip_address);
    teid_dl = htobe32(teid_dl);
  } else {
    key     = ue_ip_address;
    teid_dl = htole32(teid_dl);
  }

  pPFCP_Session_LookupProgram->getSessionMappingMap()->update(
      ue_ip_address, teid_dl, BPF_ANY);
}

/*****************************************************************************************************************/
// // Helper function to store UE QFI
// void SessionProgramManager::storeUeQfiTeidMap(
//     std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
//     uint32_t ue_ip_address, uint8_t qfi, uint32_t teid_ul) {
//   s_ue_qfi key;

//   __builtin_memset(&key, 0, sizeof(struct s_ue_qfi));

//   if (is_little_endian()) {
//     key.src_ip = htole32(ue_ip_address);
//     teid_ul    = htobe32(teid_ul);
//   } else {
//     key.src_ip = ue_ip_address;
//     teid_ul    = htole32(teid_ul);
//   }

//   key.qfi = qfi;

//   pPFCP_Session_LookupProgram->getUeQfiTeidMap()->update(key, teid_ul,
//   BPF_ANY);
// }

/*****************************************************************************************************************/
// Helper function to store the FAR in the FAR program
void SessionProgramManager::storeFARInFARMap(
    std::shared_ptr<FARProgram> pFARProgram,
    std::shared_ptr<pfcp::pfcp_far> pFar) {
  uint8_t index   = 0;
  pfcp_far_t_ far = createFar(pFar);
  pFARProgram->getFARMap()->update(index, far, BPF_ANY);
}

/*****************************************************************************************************************/
// Function to update ARP table with remoteN6 IP and MAC address
void SessionProgramManager::updateARPTableForN6(
    std::shared_ptr<FARProgram> pFARProgram, uint32_t dnIP, uint32_t upfn6IP) {
  try {
    NextHopFinder finder;
    // uint32_t remoteN6 = getRemoteIP(upfn6IP, dnIP);
    uint32_t ipnexremoteN6hop = (is_little_endian()) ?
                                    htole32(getRemoteIP(upfn6IP, dnIP)) :
                                    getRemoteIP(upfn6IP, dnIP);
    auto remoteN6MAC          = finder.retrieveNextHopMAC(ipnexremoteN6hop);

    struct s_arp_mapping map_table;
    memset(&map_table, 0, sizeof(struct s_arp_mapping));
    memcpy(map_table.mac_address, remoteN6MAC->ether_addr_octet, 6);
    map_table.ipv4_address = ipnexremoteN6hop;

    pFARProgram->getArpTableMap()->update(upfn6IP, map_table, BPF_ANY);
  } catch (const std::exception& ex) {
    Logger::upf_app().error(
        "Error: The ARP table was not updated for N6 Next HOP");
  }
}

// /*****************************************************************************************************************/
// Function to update ARP table with remoteN3 IP and MAC address
void SessionProgramManager::updateARPTableForN3(
    std::shared_ptr<FARProgram> pFARProgram, uint32_t gNodeBIP,
    uint32_t upfn3IP, uint32_t seid) {
  try {
    NextHopFinder finder;

    // uint32_t remoteN3 = getRemoteIP(upfn3IP, gNodeBIP);

    uint32_t ipnexremoteN3hop = (is_little_endian()) ?
                                    htole32(getRemoteIP(upfn3IP, gNodeBIP)) :
                                    getRemoteIP(upfn3IP, gNodeBIP);
    auto remoteN3MAC          = finder.retrieveNextHopMAC(ipnexremoteN3hop);

    struct s_arp_mapping map_table;
    memset(&map_table, 0, sizeof(struct s_arp_mapping));
    memcpy(map_table.mac_address, remoteN3MAC->ether_addr_octet, 6);
    map_table.ipv4_address = ipnexremoteN3hop;

    pFARProgram->getArpTableMap()->update(upfn3IP, map_table, BPF_ANY);

    for (auto it = farPrograms->begin(); it != farPrograms->end(); ++it) {
      // Access the members of the 'farprograms' struct
      uint32_t savedSeid                      = it->seid;
      std::shared_ptr<FARProgram> pFARProgram = it->pFARProgram;

      if (savedSeid == seid) {
        pFARProgram->getArpTableMap()->update(upfn3IP, map_table, BPF_ANY);
      }
    }
  } catch (const std::exception& ex) {
    // Handle the exception here or log it for debugging
    // Note: It's better to handle exceptions rather than ignoring them.
    Logger::upf_app().error(
        "Error: The ARP table was not updated for N3 Next HOP");
  }
}

/*****************************************************************************************************************/
// Helper function to save SEID with FAR program
void SessionProgramManager::saveSeidWithinFARProgram(
    uint32_t seid, std::shared_ptr<FARProgram> pFARProgram,
    const next_rule_prog_index_key& key) {
  // Map the deployed pipeline to the seid.
  // The seid will be used to detroy the pipeline.
  mSessionProgramsMap[seid] =
      std::make_shared<SessionPrograms>(key, pFARProgram);
  addFarProgram(seid, pFARProgram);
}

/*****************************************************************************************************************/
uint32_t SessionProgramManager::getGnodebIp(
    std::shared_ptr<pfcp::pfcp_far> pFar) {
  pfcp::forwarding_parameters foward_param;

  if (not pFar->get(foward_param)) {
    Logger::upf_app().error(
        "Could not retrieve the forwarding parameters from FAR");
    throw std::runtime_error("gNodeB IP cannot be retrieved");
  }

  pfcp::ue_ip_address_t gNBIpAddress;
  gNBIpAddress.v4 = 1;
  gNBIpAddress.ipv4_address =
      foward_param.outer_header_creation.second.ipv4_address;

  return gNBIpAddress.ipv4_address.s_addr;
}

/*****************************************************************************************************************/
// Function to create a pipeline for a given session and FAR
void SessionProgramManager::createPipeline(
    uint32_t seid, uint32_t teid1, uint8_t sourceInterface,
    uint32_t ueIpAddress, std::shared_ptr<pfcp::pfcp_far> pFar,
    bool isModification, uint32_t teid2) {
  next_rule_prog_index_key key;
  initializeNextRuleProgIndexKey(key, teid1, ueIpAddress, sourceInterface);

  Logger::upf_app().debug("Instantiate a new FARProgram");
  std::shared_ptr<FARProgram> pFARProgram = std::make_shared<FARProgram>();
  pFARProgram->setup();

  auto pPFCP_Session_LookupProgram =
      UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();

  storeFarProgramIndexInNextProgRuleIndexMap(
      pFARProgram, key, pPFCP_Session_LookupProgram);

  Logger::upf_app().debug("Store FAR in the FAR program");
  // Logger::upf_app().debug("############ QFI2 %u ###########", qfi);
  storeFARInFARMap(pFARProgram, pFar);

  uint32_t dnIP    = upf_cfg.remote_n6.s_addr;
  uint32_t upfn3IP = upf_cfg.n3.addr4.s_addr;
  uint32_t upfn6IP = upf_cfg.n6.addr4.s_addr;

  Logger::upf_app().warn(
      "TODO: Try to extract the updateARPTableForN6 for the if and else to "
      "run it only once");
  // // Launch a separate thread to update ARP table map
  //   std::thread arpUpdateThread2([this, pFARProgram, dnIP, upfn6IP]() {
  //     updateARPTableForN6(pFARProgram, dnIP, upfn6IP);
  //   });
  // arpUpdateThread2.detach();

  if (isModification) {
    storeSessionMappingMap(pPFCP_Session_LookupProgram, ueIpAddress, teid1);
    uint32_t gNodeBIP = getGnodebIp(pFar);

    std::thread arpUpdateThread1(
        [this, pFARProgram, seid, gNodeBIP, dnIP, upfn3IP, upfn6IP]() {
          updateARPTableForN6(pFARProgram, dnIP, upfn6IP);
          updateARPTableForN3(pFARProgram, gNodeBIP, upfn3IP, seid);
        });

    // Detach the thread since we don't need to join it
    arpUpdateThread1.detach();
  } else {
    // Launch a separate thread to update ARP table map
    std::thread arpUpdateThread2([this, pFARProgram, dnIP, upfn6IP]() {
      updateARPTableForN6(pFARProgram, dnIP, upfn6IP);
    });

    arpUpdateThread2.detach();
    saveSeidWithinFARProgram(seid, pFARProgram, key);
  }
}
/*****************************************************************************************************************/

// void SessionProgramManager::createPipeline(
//     uint32_t seid, uint32_t teid1, uint8_t sourceInterface,
//     uint32_t ueIpAddress, std::shared_ptr<pfcp::pfcp_far> pFar,
//     bool isModification, uint32_t teid2) {

//     struct next_rule_prog_index_key key;

//     u32 id;
//     s32 fd;

// /*******************/
//     __builtin_memset(&key, 0, sizeof(struct next_rule_prog_index_key));

//     if (is_little_endian()) {
//       key.teid         = htobe32(teid1);
//       key.ipv4_address = htole32(ueIpAddress);
//     } else {
//       key.teid         = htole32(teid1);
//       key.ipv4_address = ueIpAddress;
//     }

//     key.source_value = sourceInterface;

// /*******************/
//     Logger::upf_app().debug("Instantiate a new FARProgram");
//     std::shared_ptr<FARProgram> pFARProgram = std::make_shared<FARProgram>();
//     pFARProgram->setup();
// /*******************/

//     Logger::upf_app().debug("Store FARProgram index in the UPFProgram");
//     auto pPFCP_Session_LookupProgram =
//         UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();
//     id = pFARProgram->getId();
//     fd = pFARProgram->getFd();

//     // TODO: Get the nextProgRule index from a pool of values.
//     pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->update(
//         key, id, BPF_ANY);
//     pPFCP_Session_LookupProgram->getNextProgRuleMap()->update(id, fd,
//     BPF_ANY);

// /*******************/

//     Logger::upf_app().debug("Store FAR in the FAR program");
//     uint8_t index   = 0;
//     pfcp_far_t_ far = createFar(pFar);
//     pFARProgram->getFARMap()->update(index, far, BPF_ANY);

// /*******************/

//     uint32_t dnIP    = upf_cfg.remote_n6.s_addr;
//     uint32_t upfn3IP = upf_cfg.n3.addr4.s_addr;
//     uint32_t upfn6IP = upf_cfg.n6.addr4.s_addr;

//     if (isModification) {
//       pfcp::forwarding_parameters foward_param;

//       if (not pFar->get(foward_param)) {
//         Logger::upf_app().error(
//             "Could not retrieve the forwarding parameters from FAR");
//       }

//       pfcp::ue_ip_address_t gNBIpAddress;
//       gNBIpAddress.v4 = 1;
//       gNBIpAddress.ipv4_address =
//           foward_param.outer_header_creation.second.ipv4_address;

//       uint32_t gNodeBIP = gNBIpAddress.ipv4_address.s_addr;
//       // Launch a separate thread to update ARP table map

//       std::thread arpUpdateThread1([this, pFARProgram, seid, gNodeBIP, dnIP,
//                                     upfn3IP, upfn6IP]() {
//         try {
//           NextHopFinder finder;

//           uint32_t remoteN6 = getRemoteIP(upfn6IP, dnIP);
//           auto remoteN6MAC  = finder.retrieveNextHopMAC(remoteN6);

//           uint32_t ipnexremoteN6hop =
//               (is_little_endian()) ? htole32(remoteN6) : remoteN6;
//           pFARProgram->getArpTableMap()->update(
//               ipnexremoteN6hop, remoteN6MAC->ether_addr_octet, BPF_ANY);

//           uint32_t remoteN3 = getRemoteIP(upfn3IP, gNodeBIP);
//           auto remoteN3MAC  = finder.retrieveNextHopMAC(remoteN3);

//           uint32_t ipnexremoteN3hop =
//               (is_little_endian()) ? htole32(remoteN3) : remoteN3;
//           pFARProgram->getArpTableMap()->update(
//               ipnexremoteN3hop, remoteN3MAC->ether_addr_octet, BPF_ANY);

//           // updateArpTableMap(pFARProgram, upfn3IP, ipnexthop);
//           // updateArpTableMap(pFARProgram, upfn6IP, ipnexthop);

//           for (auto it = farPrograms->begin(); it != farPrograms->end();
//           ++it) {
//             // Access the members of the 'farprograms' struct
//             uint32_t savedSeid                      = it->seid;
//             std::shared_ptr<FARProgram> pFARProgram = it->pFARProgram;

//             if (savedSeid == seid) {
//               pFARProgram->getArpTableMap()->update(
//                   ipnexremoteN3hop, remoteN3MAC->ether_addr_octet, BPF_ANY);
//             }
//           }
//         } catch (const std::exception& ex) {
//           // Handle the exception here or log it for debugging
//           // Note: It's better to handle exceptions rather than ignoring
//           them. Logger::upf_app().error(
//               "Error: The ARP table was not updated for N3 Next HOP");
//         }
//       });

//       // Detach the thread since we don't need to join it
//       arpUpdateThread1.detach();
//     } else {
//       // Launch a separate thread to update ARP table map

//       std::thread arpUpdateThread2([this, pFARProgram, dnIP, upfn6IP]() {
//         try {
//           // updateArpTableMap(pFARProgram, upfn6IP, ipnexthop);
//           NextHopFinder finder;
//           uint32_t remoteN6 = getRemoteIP(upfn6IP, dnIP);
//           auto remoteN6MAC  = finder.retrieveNextHopMAC(remoteN6);

//           uint32_t ipnexremoteN6hop =
//               (is_little_endian()) ? htole32(remoteN6) : remoteN6;
//           pFARProgram->getArpTableMap()->update(
//               ipnexremoteN6hop, remoteN6MAC->ether_addr_octet, BPF_ANY);

//         } catch (const std::exception& ex) {
//           Logger::upf_app().error(
//               "Error: The ARP table was not updated for N6 Next HOP");
//         }
//       });
//       arpUpdateThread2.detach();

//       // Map the pipeline deployed to the seid. The seid will be used to
//       // detroyed it.
//       mSessionProgramsMap[seid] =
//           std::make_shared<SessionPrograms>(key, pFARProgram);
//       addFarProgram(seid, pFARProgram);
//     }
//   }

/*****************************************************************************************************************/
// void
// SessionProgramManager::updateMap(std::shared_ptr<PFCP_Session_LookupProgram>
// pPFCP_Session_LookupProgram,
//     uint32_t seid, uint32_t teid_ul, uint32_t src_ip, uint32_t teid_dl) {

//    struct s_traffic traffic_key;
//    __builtin_memset(&traffic_key, 0, sizeof(struct s_traffic));

//     if (is_little_endian()) {
//       traffic_key.teid_ul         = htobe32(teid_ul);
//       traffic_key.src_ip = htole32(src_ip);
//     } else {
//       traffic_key.teid_ul         = htole32(teid_ul);
//       traffic_key.src_ip = src_ip;
//     }

//     pPFCP_Session_LookupProgram->getTrafficMap()->update(
//       traffic_key, teid_dl, BPF_ANY);
// }

/*****************************************************************************************************************/
// void SessionProgramManager::updatePipeline(
//     uint32_t seid, uint32_t teid, uint32_t gNBIpAddress, bool
//     isModification) {
//   struct next_rule_prog_index_key key_to_find;
//   u32 id;
//   s32 fd;

//   __builtin_memset(&key_to_find, 0, sizeof(struct
//   next_rule_prog_index_key));

//   if (is_little_endian()) {
//     key_to_find.teid         = htobe32(teid);
//     key_to_find.ipv4_address = htole32(gNBIpAddress);
//   } else {
//     key_to_find.teid         = htole32(teid);
//     key_to_find.ipv4_address = gNBIpAddress;
//   }

//   key_to_find.source_value = INTERFACE_VALUE_ACCESS;

//   // Logger::upf_app().debug("Instantiate a new FARProgram");
//   // std::shared_ptr<FARProgram> pFARProgram =
//   std::make_shared<FARProgram>();
//   // pFARProgram->setup();

//   // Logger::upf_app().debug("Store FARProgram index in the UPFProgram");
//   auto pPFCP_Session_LookupProgram =
//       UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();
//   // id = pFARProgram->getId();
//   // fd = pFARProgram->getFd();

//   // TODO: Get the nextProgRule index from a pool of values.
//   struct next_rule_prog_index_key key = {}, next_key;
//   // auto fd_next_rule_key =
//   // pPFCP_Session_LookupProgram->getNextProgRuleIndexMap();

//   while
//   ((pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->get_next_elem(
//              key, next_key)) == 0) {
//     key = next_key;
//     void* value;

//     if ((key_to_find.teid == next_key.teid) &&
//         (key_to_find.source_value == next_key.source_value) &&
//         (key_to_find.ipv4_address != next_key.ipv4_address)) {
//       Logger::upf_app().debug(
//           "Looking for the Key <%d, %d, %d>", next_key.teid,
//           next_key.source_value, next_key.ipv4_address);

//       u_int32_t ret_val =
//           pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->lookup(
//               next_key, &value);

//       if (ret_val == 0) {
//         Logger::upf_app().debug(
//             "Updating the Key <%d, %d, %d>", next_key.teid,
//             next_key.source_value, next_key.ipv4_address);
//         pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->update(
//             key_to_find, value, BPF_ANY);

//         Logger::upf_app().debug(
//             "Deleting the Key <%d, %d, %d>", next_key.teid,
//             next_key.source_value, next_key.ipv4_address);
//         pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->remove(
//             next_key);
//       }
//     }
//   }
// }

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
        "PDU Session {} Already Exists. Cannot Create a New eBPF Program "
        "with "
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
