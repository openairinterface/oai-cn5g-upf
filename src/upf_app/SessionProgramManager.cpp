#include "SessionProgramManager.h"
#include <qer_tc_user.h>
//#include <pfcp_session_pdr_lookup_xdp_user.h>
#include "SessionPrograms.h"
#include <pfcp_session_lookup_xdp_user.h>
#include <UserPlaneComponent.h>
#include <net/if.h>  // if_nametoindex

#include <observer/OnStateChangeSessionProgramObserver.h>
#include <spdlog/fmt/ostr.h>
#include <types.h>
#include <wrappers/BPFMap.hpp>
#include "logger.hpp"
#include "helpers/NextHopFinder.hpp"
#include <errno.h>
#include <arpa/inet.h>
#include <arp_table_maps.h>
#include <session_id.h>
#include "upf_config.hpp"
#include <thread>
#include <rules_matching_pdr.h>
#include "helpers/SdfFilterParser.hpp"
#include "helpers/ConfigLoader.hpp"
#include "sdf_filter.h"

// #include <sys/utsname.h>
// #include <stdio.h>
// #include <string.h>

using namespace oai::config;
extern upf_config upf_cfg;

#define EMPTY_SLOT -1l

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define MAX_PDRS_SESSION 32
//---------------------------------------------------------------------------------------------------------------
int is_little_endian() {
  u32 value = 1;
  u8* byte  = (u8*) &value;
  return (*byte == 1);
}

// int is_little_endian() {
//   struct utsname buf;
//   uname(&buf);
//   return (
//       strstr(buf.machine, "x86_64") || strstr(buf.machine, "i386") ||
//       strstr(buf.machine, "armv7") || strstr(buf.machine, "aarch64"));
// }
//---------------------------------------------------------------------------------------------------------------
std::ostream& operator<<(
    std::ostream& Str, struct next_rule_prog_index_key const& v) {
  Str << "TEID: " << v.teid << " SOURCE INTERFACE: " << v.source_value
      << "IPv4 ADDRESS: " << v.ipv4_address;
  return Str;
}

//---------------------------------------------------------------------------------------------------------------
SessionProgramManager::SessionProgramManager() {
  for (auto& item : mProgramArray) {
    item = EMPTY_SLOT;
  }
  pfcpPrograms = std::make_shared<std::vector<pfcpprograms>>();
}

//---------------------------------------------------------------------------------------------------------------
SessionProgramManager::~SessionProgramManager() {
  removeAll();
}

//---------------------------------------------------------------------------------------------------------------
SessionProgramManager& SessionProgramManager::getInstance() {
  static SessionProgramManager sInstance;
  return sInstance;
}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::setTeidSessionMap(
    std::shared_ptr<BPFMap> pProgramsMaps) {
  mpTeidSessionMap = pProgramsMaps;
}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::addPFCPProgram(
    uint64_t seid,
    std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram) {
  pfcpprograms pfcpprogam                = {};
  pfcpprogam.seid                        = seid;
  pfcpprogam.pPFCP_Session_LookupProgram = pPFCP_Session_LookupProgram;

  pfcpPrograms->push_back(pfcpprogam);
}

//---------------------------------------------------------------------------------------------------------------
uint32_t SessionProgramManager::getRemoteIP(uint32_t upfIP, uint32_t remoteIP) {
  uint32_t ipnexthop = 0;
  if (not NextHopFinder::sameSubnet(upfIP, remoteIP)) {
    Logger::upf_app().debug("Not in the same subnet");
    ipnexthop = NextHopFinder::retrieveNextHopIP(remoteIP);
  } else {
    Logger::upf_app().debug("The same subnet");
    ipnexthop = remoteIP;
  }
  return ipnexthop;
}

//---------------------------------------------------------------------------------------------------------------
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

//---------------------------------------------------------------------------------------------------------------

pfcp_pdr_t_ SessionProgramManager::createPdr(
    std::shared_ptr<pfcp::pfcp_pdr> pPdr) {
  pfcp_pdr_t_ pdr;

  pdr.pdr_id.rule_id        = pPdr->pdr_id.rule_id;
  pdr.precedence.precedence = pPdr->precedence.second.precedence;

  pdr.far_id.far_id = pPdr->far_id.second.far_id;
  pdr.qer_id.qer_id = pPdr->qer_id.second.qer_id;
  pdr.urr_id.urr_id = pPdr->urr_id.second.urr_id;

  pdr.pdi.source_interface.interface_value =
      pPdr->pdi.second.source_interface.second.interface_value;
  pdr.pdi.fteid.teid = pPdr->pdi.second.local_fteid.second.teid;
  // pdr.pdi.network_instance    = pPdr->pdi.second.network_instance;
  pdr.pdi.ue_ip_address.ipv4_address =
      pPdr->pdi.second.ue_ip_address.second.ipv4_address.s_addr;
  //  pdr.pdi.traffic_endpoint_id = pPdr->pdi.second.traffic_endpoint_id;
  pdr.pdi.sdf_filter.length_of_flow_description =
      pPdr->pdi.second.sdf_filter.second.length_of_flow_description;
  Logger::upf_app().debug(
      "SDF Filter Lengh (%d)", pdr.pdi.sdf_filter.length_of_flow_description);

  try {
    if (pdr.pdi.sdf_filter.length_of_flow_description >=
        sizeof(pdr.pdi.sdf_filter.flow_description)) {
      Logger::upf_app().debug(
          "SDF Filter Lengh (%d) exceeds buffer size (%d), Truncating data.",
          pdr.pdi.sdf_filter.length_of_flow_description,
          sizeof(pdr.pdi.sdf_filter.flow_description));

      throw std::runtime_error("SDF filter length exceeds buffer size.");
    }

    memcpy(
        pdr.pdi.sdf_filter.flow_description,
        pPdr->pdi.second.sdf_filter.second.flow_description.c_str(),
        pdr.pdi.sdf_filter.length_of_flow_description);
  } catch (const std::bad_alloc& e) {
    // Handle memory allocation failure
    Logger::upf_app().error(
        "Memory allocation failed while copying SDF filter: {}", e.what());

    throw;  // Rethrow the exception
  } catch (const std::exception& e) {
    // Catch any other exception
    Logger::upf_app().error(
        "An error occurred while processing the SDF filter: {}", e.what());

    throw;  // Rethrow the exception
  } catch (...) {
    // Catch all other unspecified errors
    Logger::upf_app().error(
        "An unexpected error occurred while copying the SDF filter.");

    throw std::runtime_error(
        "Unexpected error occurred while copying SDF filter.");
  }

  // pdr.pdi.application_id      = pPdr->pdi.second.application_id;
  // pdr.pdi.ethernet_pdu_session_information =
  //   pPdr->pdi.second.ethernet_packet_filter;
  pdr.pdi.qfi.qfi = pPdr->pdi.second.qfi.second.qfi;
  // pdr.pdi.framed_route      = pPdr->pdi.second.framed_route;
  // pdr.pdi.framed_routing    = pPdr->pdi.second.framed_routing;
  // pdr.pdi.framed_ipv6_route = pPdr->pdi.second.framed_ipv6_route;

  memcpy(
      &pdr.activate_predefined_rules, &pPdr->activate_predefined_rules,
      sizeof(activate_predefined_rules_t_));
  // memcpy(&pdr.pdi, &pPdr->pdi, sizeof(pdi_t_));
  memcpy(
      &pdr.outer_header_removal, &pPdr->outer_header_removal,
      sizeof(outer_header_removal_t_));

  return pdr;
}

//---------------------------------------------------------------------------------------------------------------
pfcp_qer_t_ SessionProgramManager::createQer(
    std::shared_ptr<pfcp::pfcp_qer> pQer) {
  pfcp_qer_t_ qer;

  qer.qer_id.qer_id = pQer->qer_id.second.qer_id;

  qer.qer_correlation_id.qer_correlation_id =
      pQer->qer_correlation_id.second.qer_correlation_id;

  qer.gate_status.ul_gate = pQer->gate_status.second.ul_gate;
  qer.gate_status.dl_gate = pQer->gate_status.second.dl_gate;

  qer.maximum_bitrate.ul_mbr = pQer->mbr.second.ul_mbr;
  qer.maximum_bitrate.dl_mbr = pQer->mbr.second.dl_mbr;

  qer.guaranteed_bitrate.ul_gbr = pQer->gbr.second.ul_gbr;
  qer.guaranteed_bitrate.dl_gbr = pQer->gbr.second.dl_gbr;

  // qer.packet_rate.dlpr = pQer->

  // qer.dl_flow_level_marking.sci = pQer->
  qer.qos_flow_identifier.qfi = pQer->qfi.second.qfi;

  qer.reflective_qos.rqi = pQer->rqi.second.rqi;

  return qer;
}

// qfi_t qos_flow_identifier;
// rqi_t reflective_qos;

//---------------------------------------------------------------------------------------------------------------
// Helper function to initialize the key for the FARProgram
void SessionProgramManager::initializeNextRuleProgIndexKey(
    next_rule_prog_index_key& key, uint32_t teid, uint32_t ueIpAddress,
    uint8_t sourceInterface) {
  __builtin_memset(&key, 0, sizeof(struct next_rule_prog_index_key));

  if (likely(is_little_endian())) {
    key.teid         = htonl(teid);
    key.ipv4_address = htonl(ueIpAddress);
  } else {
    key.teid         = teid;
    key.ipv4_address = ueIpAddress;
  }

  key.source_value = sourceInterface;
}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::storeFarProgramIndexInNextProgRuleIndexMap(
    std::shared_ptr<pfcp::pfcp_far> pFar, const next_rule_prog_index_key& key,
    std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram) {
  pfcp_far_t_ far = createFar(pFar);
  pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->update(
      key, far, BPF_ANY);
  // pPFCP_Session_LookupProgram->getNextProgRuleMap()->update(id, fd, BPF_ANY);
}

//---------------------------------------------------------------------------------------------------------------
// Helper function to store Session mapping
void SessionProgramManager::storePduSessionInMap(
    std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
    uint32_t ue_ip_addr, uint32_t teid_ul, uint32_t teid_dl, uint64_t seid) {
  // Normalize TEIDs and SEID for little-endian systems
  if (likely(is_little_endian())) {
    ue_ip_addr = htonl(ue_ip_addr);
    teid_ul    = htonl(teid_ul);
    teid_dl    = htonl(teid_dl);
    seid       = seid;  // TODO: verify if correct
  }

  struct session_id session = {0};
  uint32_t key              = ue_ip_addr;

  // Perform the lookup
  int ret = pPFCP_Session_LookupProgram->getSessionMappingMap()->lookup(
      key, &session);

  // If the session exists, update the relevant fields
  if (ret == 0) {
    if ((session.teid_ul == 0) && (teid_ul != 0)) {
      session.teid_ul = teid_ul;
    }

    if ((session.teid_dl == 0) && (teid_dl != 0)) {
      session.teid_dl = teid_dl;
    }
  } else {
    // If no session is found, initialize it with the provided values
    session.teid_ul = teid_ul;
    session.teid_dl = teid_dl;
    session.seid    = seid;
  }

  // Update the map with the session data
  pPFCP_Session_LookupProgram->getSessionMappingMap()->update(
      key, session, BPF_ANY);
}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::updateARPTableForN6(
    std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
    uint32_t dnIP, uint32_t upfn6IP) {
  try {
    // uint32_t remoteN6 = getRemoteIP(upfn6IP, dnIP);
    uint32_t ipnexremoteN6hop = (likely(is_little_endian())) ?
                                    htole32(getRemoteIP(upfn6IP, dnIP)) :
                                    getRemoteIP(upfn6IP, dnIP);
    auto remoteN6MAC = NextHopFinder::retrieveNextHopMAC(ipnexremoteN6hop);

    struct s_arp_mapping map_table;
    memset(&map_table, 0, sizeof(struct s_arp_mapping));
    memcpy(map_table.mac_address, remoteN6MAC, 6);
    map_table.ipv4_address = ipnexremoteN6hop;

    // int max_entries =
    //     ConfigLoader::getInstance().getValue("max_arp_entries", 333);
    // Logger::upf_app().error(
    //     "************************ max_arp_entries = %d", max_entries);
    // pPFCP_Session_LookupProgram->getArpTableMap()->resize(max_entries);
    pPFCP_Session_LookupProgram->getArpTableMap()->update(
        upfn6IP, map_table, BPF_ANY);
  } catch (const std::exception& ex) {
    Logger::upf_app().error(
        "Error: The ARP table was not updated for N6 Next HOP");
  }
}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::updateARPTableForN3(
    std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
    uint32_t gNodeBIP, uint32_t upfn3IP, uint32_t seid) {
  try {
    // uint32_t remoteN3 = getRemoteIP(upfn3IP, gNodeBIP);

    uint32_t ipnexremoteN3hop = (likely(is_little_endian())) ?
                                    htole32(getRemoteIP(upfn3IP, gNodeBIP)) :
                                    getRemoteIP(upfn3IP, gNodeBIP);
    auto remoteN3MAC = NextHopFinder::retrieveNextHopMAC(ipnexremoteN3hop);

    struct s_arp_mapping map_table;
    memset(&map_table, 0, sizeof(struct s_arp_mapping));
    memcpy(map_table.mac_address, remoteN3MAC, 6);
    map_table.ipv4_address = ipnexremoteN3hop;

    // int max_entries =
    //     ConfigLoader::getInstance().getValue("max_arp_entries", 777);
    // Logger::upf_app().error(
    //     "************************ max_arp_entries = %d", max_entries);
    // pPFCP_Session_LookupProgram->getArpTableMap()->resize(max_entries);
    pPFCP_Session_LookupProgram->getArpTableMap()->update(
        upfn3IP, map_table, BPF_ANY);

    for (auto it = pfcpPrograms->begin(); it != pfcpPrograms->end(); ++it) {
      // Access the members of the 'farprograms' struct
      uint64_t savedSeid = it->seid;
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram =
          it->pPFCP_Session_LookupProgram;

      if (savedSeid == seid) {
        pPFCP_Session_LookupProgram->getArpTableMap()->update(
            upfn3IP, map_table, BPF_ANY);
      }
    }
  } catch (const std::exception& ex) {
    // Handle the exception here or log it for debugging
    // Note: It's better to handle exceptions rather than ignoring them.
    Logger::upf_app().error(
        "Error: The ARP table was not updated for N3 Next HOP");
  }
}

//---------------------------------------------------------------------------------------------------------------
// Helper function to save SEID with FAR program
void SessionProgramManager::saveSeidWithinFARProgram(
    uint64_t seid,
    std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
    const next_rule_prog_index_key& key) {
  // Map the deployed pipeline to the seid.
  // The seid will be used to destroy the pipeline.
  mSessionProgramsMap[seid] =
      std::make_shared<SessionPrograms>(key, pPFCP_Session_LookupProgram);
  addPFCPProgram(seid, pPFCP_Session_LookupProgram);
}

//---------------------------------------------------------------------------------------------------------------
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

//---------------------------------------------------------------------------------------------------------------
uint32_t SessionProgramManager::retrieveGnbIp(
    std::shared_ptr<pfcp::pfcp_session> session) {
  pfcp::forwarding_parameters foward_param;
  u32 gnbIp = 0;

  for (const auto& far : session->fars) {
    if ((far->get(foward_param)) && foward_param.outer_header_creation.first) {
      gnbIp = foward_param.outer_header_creation.second.ipv4_address.s_addr;
    }
  }

  return gnbIp;
}

//---------------------------------------------------------------------------------------------------------------
uint32_t SessionProgramManager::retrieveUeIp(
    std::shared_ptr<pfcp::pfcp_session> session) {
  pfcp::pdi pdi;
  pfcp::ue_ip_address_t ueIpAddress;
  uint32_t ueIp = 0;

  for (const auto& pdr : session->pdrs) {
    if (pdr->get(pdi) && pdi.get(ueIpAddress)) {
      ueIp = ueIpAddress.ipv4_address.s_addr;
      break;
    }
  }

  return ueIp;
}

//---------------------------------------------------------------------------------------------------------------
bool SessionProgramManager::getFar(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_far>& outFar) {
  pfcp::far_id_t farId;
  return (pdr->get(farId) && session->get(farId.far_id, outFar));
}

//---------------------------------------------------------------------------------------------------------------
bool SessionProgramManager::getQer(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_qer>& outQer) {
  pfcp::qer_id_t qerId;

  return (pdr->get(qerId) && session->get(qerId.qer_id, outQer));
}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::createPipeline(
    std::shared_ptr<pfcp::pfcp_session> session) {
  auto& logger     = Logger::upf_app();
  uint32_t dnIP    = upf_cfg.remote_n6.s_addr;
  uint32_t upfn3IP = upf_cfg.n3.addr4.s_addr;
  uint32_t upfn6IP = upf_cfg.n6.addr4.s_addr;

  if (session->pdrs.size() > MAX_PDRS_SESSION) {
    logger.error(
        "Number of PDRs within a PDU session exceeds %d, please either "
        "increase this number or remove some PDRs",
        MAX_PDRS_SESSION);
    throw std::runtime_error(
        "Number of requested PDRs exceeds the allocated size for PDRs "
        "vector:");
  }

  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::source_interface_t sourceInterface;
  uint16_t pdr_id;
  uint32_t far_id;
  next_rule_prog_index_key key;
  session_id pduSession;
  uint64_t seid = session->get_up_seid();

  auto pPFCP_Session_LookupProgram =
      UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();

  pfcp_pdr_t_ pdrs[MAX_PDRS_SESSION] = {0};
  int i                              = 0;

  // Handle Uplink PDRs
  for (const auto pdr : session->pdrs) {
    pdr_id = pdr->pdr_id.rule_id;
    logger.debug("Processing PDR %d on establishment", pdr_id);

    if (!(pdr->get(pdi) && pdi.get(sourceInterface))) {
      throw std::runtime_error(
          "Missing Mandatory IE in PDR: " + std::to_string(pdr_id));
    }

    if (!pdi.get(fteid)) {
      fteid.teid = -1;
      logger.warn(
          "FTEID is missing for PDR %d. CH bit: %s", pdr_id,
          fteid.ch ? "Set" : "Not Set");
      /*
       * TODO: Implement the logic when fteid is not present
       */
    }
    if (!pdi.get(ueIpAddress)) {
      ueIpAddress.ipv4_address.s_addr = 0;
      logger.warn("UE IP Address is missing for PDR %d", pdr_id);

      /*
       * TODO: Implement the logic when ipv4_address.s_addr is not present
       */
    }
    // sessionIds(pduSession, seid, fteid.teid, 0);

    storePduSessionInMap(
        pPFCP_Session_LookupProgram, ueIpAddress.ipv4_address.s_addr,
        fteid.teid, 0, seid);

    std::shared_ptr<pfcp::pfcp_far> far;
    if (!getFar(session, pdr, far)) {
      throw std::runtime_error(
          "Error retrieving FAR for PDR ID: " + std::to_string(pdr_id));
    }

    /*
     * On the Uplink see if there is QER applied for downlink
     */
    std::shared_ptr<pfcp::pfcp_qer> qer;
    if (!getQer(session, pdr, qer)) {
      logger.debug("Missing qer for pdr %d", pdr_id);
    }

    struct rules_match_pdr rules = {0};
    rules.far                    = createFar(far);
    rules.qer                    = createQer(qer);

    struct pdrs_per_session pdr_key = {0};
    pdr_key.pdr_id                  = pdr_id;
    pdr_key.seid                    = seid;

    pPFCP_Session_LookupProgram->getRulesMatchPdrMap()->update(
        pdr_key, rules, BPF_ANY);

    // far_id = far->far_id.far_id;
    // initializeNextRuleProgIndexKey(key, teid1, ueIpAddress,
    // sourceInterface);

    // storeFarProgramIndexInNextProgRuleIndexMap(
    //     far, key, pPFCP_Session_LookupProgram);

    std::thread arpUpdateThread(
        [this, pPFCP_Session_LookupProgram, dnIP, upfn6IP]() {
          updateARPTableForN6(pPFCP_Session_LookupProgram, dnIP, upfn6IP);
        });
    arpUpdateThread.detach();
    // saveSeidWithinFARProgram(seid, pPFCP_Session_LookupProgram, key);
    /*
    TO BE CONTINUED
    ..................
    */

    pdrs[i] = createPdr(pdr);
    i++;
  }

  pPFCP_Session_LookupProgram->getSessionPdrsMap()->update(seid, pdrs, BPF_ANY);
  /*
  TO BE CONTINUED: We Shall treat the case where there are downlink PDRs in
  the establishment request. To be done later
  ..................
  */
}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::modifyPipeline(
    std::shared_ptr<pfcp::pfcp_session> session, uint32_t teid_ul,
    uint32_t teid_dl) {
  auto& logger = Logger::upf_app();

  uint32_t dnIp    = upf_cfg.remote_n6.s_addr;
  uint32_t upfn3Ip = upf_cfg.n3.addr4.s_addr;
  uint32_t upfn6Ip = upf_cfg.n6.addr4.s_addr;

  uint64_t seid   = session->get_up_seid();
  uint32_t pdr_id = 0;

  uint32_t ueIp  = retrieveUeIp(session);
  uint32_t gnbIp = retrieveGnbIp(session);

  if (!ueIp) {
    logger.error(
        "Missing UE IP Address. Handeling this case not implemented yet!");
    throw std::runtime_error(
        "Missing UE IP Address. Use case not Yet implemented");
  }

  if (!gnbIp) {
    logger.error("Missing gnb IP. Handeling this case not implemented yet!");
    throw std::runtime_error("Missing gnb IP. Use case not Yet implemented");
  }

  if (session->pdrs.size() > MAX_PDRS_SESSION) {
    logger.error(
        "Number of PDRs within a PDU session exceeds %d, please either "
        "increase this number or remove some PDRs",
        MAX_PDRS_SESSION);
    throw std::runtime_error(
        "Number of requested PDRs exceeds the allocated size for PDRs "
        "vector:");
  }

  bool enforcing_qos                  = !session->qers_downlink.empty();
  const bool isBpfAccelerationEnabled = upf_cfg.enable_bpf_datapath;
  const bool isQosEnabled = isBpfAccelerationEnabled && upf_cfg.enable_qos;
  auto pPFCP_Session_LookupProgram =
      UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();

  if (isQosEnabled && enforcing_qos) {
    uint32_t value = 1;
    pPFCP_Session_LookupProgram->getQosEnablingMap()->update(
        seid, value, BPF_ANY);

    logger.debug("Instantiate a new QERProgram");
    std::shared_ptr<QERProgram> pQERProgram = std::make_shared<QERProgram>();
    pQERProgram->setup(seid, session->qers_downlink, session->pdrs_downlink);
  }

  storePduSessionInMap(
      pPFCP_Session_LookupProgram, ueIp, teid_ul, teid_dl, seid);

  std::thread arpUpdateThread([this, pPFCP_Session_LookupProgram, seid, gnbIp,
                               dnIp, upfn3Ip, upfn6Ip]() {
    updateARPTableForN6(pPFCP_Session_LookupProgram, dnIp, upfn6Ip);
    updateARPTableForN3(pPFCP_Session_LookupProgram, gnbIp, upfn3Ip, seid);
  });

  arpUpdateThread.detach();

  pfcp_pdr_t_ pdrs[MAX_PDRS_SESSION] = {0};
  int i                              = 0;

  for (const auto& pdr : session->pdrs) {
    pdr_id = pdr->pdr_id.rule_id;
    logger.debug("Processing PDR %d on Modification", pdr_id);
    std::shared_ptr<pfcp::pfcp_far> far;
    std::shared_ptr<pfcp::pfcp_qer> qer;

    if (!getFar(session, pdr, far)) {
      throw std::runtime_error(
          "Error retrieving FAR for PDR ID: " + std::to_string(pdr_id));
    }

    if (!getQer(session, pdr, qer)) {
      logger.debug("Missing qer for pdr %d", pdr_id);
    }

    struct rules_match_pdr rules = {0};
    rules.far                    = createFar(far);
    rules.qer                    = createQer(qer);

    struct pdrs_per_session pdr_key = {0};
    pdr_key.pdr_id                  = pdr_id;
    pdr_key.seid                    = seid;

    pPFCP_Session_LookupProgram->getRulesMatchPdrMap()->update(
        pdr_key, rules, BPF_ANY);

    // Parse the SDF Flow Description
    if (pdr->qer_id.first) {
      pfcp::pdi pdi;
      pfcp::sdf_filter_t sdf;
      struct sdf_filtr sdfFilter;
      std::string flowDescription;

      if (pdr->get(pdi) && pdi.get(sdf)) {
        if (sdf.fd && sdf.length_of_flow_description > 0)
          flowDescription = sdf.flow_description;

        uint32_t qfi = getQer(session, pdr, qer) ? qer->qfi.second.qfi : 0;

        if (qfi != 0) {
          pdi.qfi.first      = true;
          pdi.qfi.second.qfi = qfi;
          pdr->set(pdi);
        }
        auto filterInfo = SdfFilterParser::ParseSdfFilter(flowDescription);
        if (filterInfo) {
          sdfFilter              = *filterInfo;
          sdfFilter.session.seid = seid;
          sdfFilter.session.qfi  = qfi;

          // struct sdfs_per_session sdf_key = {0};
          // sdf_key.qer_id                  = pdr->qer_id.second.qer_id;
          // sdf_key.seid                    = seid;
          struct session_qfi sdf_key = {0};
          sdf_key.qfi                = qfi;
          sdf_key.seid               = seid;

          pPFCP_Session_LookupProgram->getSdfFilterMap()->update(
              sdf_key, sdfFilter, BPF_ANY);
        }
      }
    }

    pdrs[i] = createPdr(pdr);
    i++;
  }

  pPFCP_Session_LookupProgram->getSessionPdrsMap()->update(seid, pdrs, BPF_ANY);
}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::createPipeline(
    uint64_t seid, uint32_t teid1, uint8_t sourceInterface,
    uint32_t ueIpAddress, std::shared_ptr<pfcp::pfcp_far> pFar,
    std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer,
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs, bool isModification,
    uint32_t teid2) {
  uint32_t dnIP    = upf_cfg.remote_n6.s_addr;
  uint32_t upfn3IP = upf_cfg.n3.addr4.s_addr;
  uint32_t upfn6IP = upf_cfg.n6.addr4.s_addr;
  uint32_t far_id  = pFar->far_id.far_id;

  next_rule_prog_index_key key;

  // for each PDR get the key and save the appropriate FAR
  initializeNextRuleProgIndexKey(key, teid1, ueIpAddress, sourceInterface);

  bool enforcing_qos                  = !pQer.empty();
  const bool isBpfAccelerationEnabled = upf_cfg.enable_bpf_datapath;
  const bool isQosEnabled = isBpfAccelerationEnabled && upf_cfg.enable_qos;
  if (isQosEnabled && enforcing_qos) {
    Logger::upf_app().debug("Instantiate a new QERProgram ");
    std::shared_ptr<QERProgram> pQERProgram = std::make_shared<QERProgram>();
    Logger::upf_app().debug("PDRs Vector size %d", pdrs.size());
    pQERProgram->setup(seid, pQer, pdrs);
  }

  auto pPFCP_Session_LookupProgram =
      UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();
  storeFarProgramIndexInNextProgRuleIndexMap(
      pFar, key, pPFCP_Session_LookupProgram);

  // until here the for loop over pdrs to save key and far

  if (isModification) {
    storePduSessionInMap(
        pPFCP_Session_LookupProgram, ueIpAddress, 0, teid1, seid);

    uint32_t gNodeBIP = getGnodebIp(pFar);

    std::thread arpUpdateThread1([this, pPFCP_Session_LookupProgram, seid,
                                  gNodeBIP, dnIP, upfn3IP, upfn6IP]() {
      updateARPTableForN6(pPFCP_Session_LookupProgram, dnIP, upfn6IP);
      updateARPTableForN3(pPFCP_Session_LookupProgram, gNodeBIP, upfn3IP, seid);
    });

    // Detach the thread since we don't need to join it
    arpUpdateThread1.detach();
  } else {
    storePduSessionInMap(
        pPFCP_Session_LookupProgram, ueIpAddress, teid1, 0, seid);
    // Launch a separate thread to update ARP table map
    std::thread arpUpdateThread2(
        [this, pPFCP_Session_LookupProgram, dnIP, upfn6IP]() {
          updateARPTableForN6(pPFCP_Session_LookupProgram, dnIP, upfn6IP);
        });
    arpUpdateThread2.detach();
    saveSeidWithinFARProgram(seid, pPFCP_Session_LookupProgram, key);
  }
}

// void SessionProgramManager::createPipeline(
//     uint64_t seid, uint32_t teid1, uint8_t sourceInterface,
//     uint32_t ueIpAddress, std::shared_ptr<pfcp::pfcp_far> pFar,
//     std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer,
//     std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs, bool isModification,
//     uint32_t teid2) {
//   uint32_t dnIP    = upf_cfg.remote_n6.s_addr;
//   uint32_t upfn3IP = upf_cfg.n3.addr4.s_addr;
//   uint32_t upfn6IP = upf_cfg.n6.addr4.s_addr;
//   uint32_t far_id  = pFar->far_id.far_id;

//   next_rule_prog_index_key key;

//   // for each PDR get the key and save the appropriate FAR
//   initializeNextRuleProgIndexKey(key, teid1, ueIpAddress, sourceInterface);

//   bool enforcing_qos                  = !pQer.empty();
//   const bool isBpfAccelerationEnabled = upf_cfg.enable_bpf_datapath;
//   const bool isQosEnabled = isBpfAccelerationEnabled && upf_cfg.enable_qos;

//   if (isQosEnabled && enforcing_qos) {
//     Logger::upf_app().debug("Instantiate a new QERProgram ");
//     std::shared_ptr<QERProgram> pQERProgram =
//     std::make_shared<QERProgram>(); Logger::upf_app().debug("PDRs Vector
//     size %d", pdrs.size()); pQERProgram->setup(seid, pQer, pdrs);
//   }

//   auto pPFCP_Session_LookupProgram =
//       UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();
//   storeFarProgramIndexInNextProgRuleIndexMap(
//       pFar, key, pPFCP_Session_LookupProgram);

//   // until here the for loop over pdrs to save key and far

//   if (isModification) {
//     storePduSessionInMap(
//         pPFCP_Session_LookupProgram, ueIpAddress, 0, teid1, seid);

//     uint32_t gNodeBIP = getGnodebIp(pFar);

//     std::thread arpUpdateThread1([this, pPFCP_Session_LookupProgram, seid,
//                                   gNodeBIP, dnIP, upfn3IP, upfn6IP]() {
//       updateARPTableForN6(pPFCP_Session_LookupProgram, dnIP, upfn6IP);
//       updateARPTableForN3(pPFCP_Session_LookupProgram, gNodeBIP, upfn3IP,
//       seid);
//     });

//     // Detach the thread since we don't need to join it
//     arpUpdateThread1.detach();
//   } else {
//     storePduSessionInMap(
//         pPFCP_Session_LookupProgram, ueIpAddress, teid1, 0, seid);
//     // Launch a separate thread to update ARP table map
//     std::thread arpUpdateThread2(
//         [this, pPFCP_Session_LookupProgram, dnIP, upfn6IP]() {
//           updateARPTableForN6(pPFCP_Session_LookupProgram, dnIP, upfn6IP);
//         });
//     arpUpdateThread2.detach();
//     saveSeidWithinFARProgram(seid, pPFCP_Session_LookupProgram, key);
//   }
// }

// void SessionProgramManager::addPdrPipeline(pdr) {}
// void SessionProgramManager::addFarPipeline(far) {}
// void SessionProgramManager::addQerPipeline(qer) {}

// void SessionProgramManager::updatePdrPipeline(pdr) {}
// void SessionProgramManager::updateFarPipeline(far) {}
// void SessionProgramManager::updateQerPipeline(qer) {}

// void SessionProgramManager::deletePdrPipeline(pdr) {}
// void SessionProgramManager::deleteFarPipeline(far) {}
// void SessionProgramManager::deleteQerPipeline(qer) {}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::removePipeline(uint64_t seid) {
  Logger::upf_app().debug("Clean the different eBPF maps");
  auto it = mSessionProgramsMap.find(seid);

  if (it == mSessionProgramsMap.end()) {
    Logger::upf_app().error("Session with SEID: %lu Does Not Exist", seid);
  }

  Logger::upf_app().debug(
      "Delete the SessionPrograms object. It will release the pipeline");

  auto key = it->second->getKey();

  // it->second.reset();

  // mSessionProgramsMap.erase(seid);

  Logger::upf_app().debug("Clean PDU Session from the entry program's map");
  // auto pPFCP_Session_LookupProgram =
  //     UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();
  // pPFCP_Session_LookupProgram->getNextProgRuleIndexMap()->remove(key);
}

//---------------------------------------------------------------------------------------------------------------
// void SessionProgramManager::create(uint64_t seid) {
//   // Check if there is a key with seid value.
//   // TODO: Check if can be abstract the programMap.

//   if (mSessionProgramMap.find(seid) != mSessionProgramMap.end()) {
//     Logger::upf_app().error(
//         "PDU Session {} Already Exists. Cannot Create a New eBPF Program
//         " "with " "the same " "key", seid);
//     throw std::runtime_error(
//         "Cannot Create a New eBPF program with Key (seid)");
//   }

//   // Instantiate a new PFCP_Session_PDR_LookupProgram
//   auto udpInterface =
//   UserPlaneComponent::getInstance().getUDPInterface(); auto gtpInterface
//   = UserPlaneComponent::getInstance().getGTPInterface();
//   std::shared_ptr<PFCP_Session_PDR_LookupProgram>
//       pPFCP_Session_PDR_LookupProgram =
//           std::make_shared<PFCP_Session_PDR_LookupProgram>(
//               gtpInterface, udpInterface);
//   // pPFCP_Session_PDR_LookupProgram->setup();

//   // Initialize key egress interface map.
//   uint32_t udpInterfaceIndex = if_nametoindex(udpInterface.c_str());
//   uint32_t gtpInterfaceIndex = if_nametoindex(gtpInterface.c_str());

//   uint32_t uplinkId   = static_cast<uint32_t>(FlowDirection::UPLINK);
//   uint32_t downlinkId = static_cast<uint32_t>(FlowDirection::DOWNLINK);

//   pPFCP_Session_PDR_LookupProgram->getEgressInterfaceMap()->update(
//       uplinkId, udpInterfaceIndex, BPF_ANY);
//   pPFCP_Session_PDR_LookupProgram->getEgressInterfaceMap()->update(
//       downlinkId, gtpInterfaceIndex, BPF_ANY);

//   // Update the PFCP_Session_PDR_LookupProgram map.
//   mSessionProgramMap.insert(
//       std::pair<uint32_t,
//       std::shared_ptr<PFCP_Session_PDR_LookupProgram>>(
//           seid, pPFCP_Session_PDR_LookupProgram));
// }

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::remove(uint64_t seid) {
  //   auto sessionProgram = findSessionProgram(seid);
  //   if (!sessionProgram) {
  //     Logger::upf_app().error(
  //         "The PDU session %d does not exist. Cannot be removed", seid);
  //     throw std::runtime_error("The session does not exist. Cannot be
  //     removed");
  //   }
  //   sessionProgram->tearDown();
  //   mSessionProgramMap.erase(seid);

  // TODO: UPdate this code with keysight
}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::removeAll() {
  //   for (auto pair : mSessionProgramMap) {
  //     pair.second->tearDown();

  //     // Notify observer that a PFCP_Session_PDR_LookupProgram was
  //     removed.
  //     mpOnNewSessionProgramObserver->onDestroySessionProgram(pair.first);
  //   }
  //   mSessionProgramMap.clear();
  /*
   * TODO: CHECK WITH Keysight
   */
}

//---------------------------------------------------------------------------------------------------------------
void SessionProgramManager::setOnNewSessionObserver(
    OnStateChangeSessionProgramObserver* pObserver) {
  mpOnNewSessionProgramObserver = pObserver;
}

//---------------------------------------------------------------------------------------------------------------
std::shared_ptr<SessionPrograms> SessionProgramManager::findSessionPrograms(
    uint64_t seid) {
  std::shared_ptr<SessionPrograms> pSessionPrograms;

  auto it = mSessionProgramsMap.find(seid);
  if (it != mSessionProgramsMap.end()) {
    pSessionPrograms = it->second;
  }

  return pSessionPrograms;
}

//---------------------------------------------------------------------------------------------------------------
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
