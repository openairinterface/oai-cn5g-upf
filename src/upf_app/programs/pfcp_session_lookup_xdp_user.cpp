#include "pfcp_session_lookup_xdp_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>     // bpf calls
#include <bpf/libbpf.h>  // bpf wrappers
#include <iostream>      // cout
#include <stdexcept>     // exception
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces.h"
#include "logger.hpp"

/*---------------------------------------------------------------------------------------------------------------*/
int is_little_endian2() {
  u32 value = 1;
  u8* byte  = (u8*) &value;
  return (*byte == 1);
}

/*---------------------------------------------------------------------------------------------------------------*/
PFCP_Session_LookupProgram::PFCP_Session_LookupProgram(
    const std::string& gtpInterface, const std::string& udpInterface)
    : mGTPInterface(gtpInterface), mUDPInterface(udpInterface) {
  mpLifeCycle = std::make_shared<PFCP_Session_LookupProgramLifeCycle>(
      pfcp_session_lookup_xdp_kernel_c__open,
      pfcp_session_lookup_xdp_kernel_c__load,
      pfcp_session_lookup_xdp_kernel_c__attach,
      pfcp_session_lookup_xdp_kernel_c__destroy);
}

/*---------------------------------------------------------------------------------------------------------------*/
PFCP_Session_LookupProgram::~PFCP_Session_LookupProgram() {}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::setup() {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  // Entry point interface
  if (mUDPInterface.empty() || mGTPInterface.empty()) {
    Logger::upf_app().error("GTP or UDP interface not defined!");
    throw std::runtime_error("GTP or UDP interface not defined!");
  }

  Logger::upf_app().debug(
      "Link UDP interface to interface %s", mUDPInterface.c_str());
  mpLifeCycle->link("xdp_entry_point", mUDPInterface.c_str());

  Logger::upf_app().debug(
      "Link GTP interface to interface %s", mGTPInterface.c_str());
  mpLifeCycle->link("xdp_entry_point", mGTPInterface.c_str());
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMaps> PFCP_Session_LookupProgram::getMaps() {
  return mpMaps;
}

/*---------------------------------------------------------------------------------------------------------------*/
// TODO: Check when kill when running.
// It was noted the infinity loop.
void PFCP_Session_LookupProgram::tearDown() {
  mpLifeCycle->tearDown();
}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::updateProgramMap(uint32_t key, uint32_t fd) {
  mpTeidSessionMap->update(key, fd, BPF_ANY);
}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::removeProgramMap(uint32_t key) {
  s32 fd;
  // Remove only if exists.
  if (mpTeidSessionMap->lookup(key, &fd) == 0) {
    mpTeidSessionMap->remove(key);
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getTeidSessionMap() const {
  return mpTeidSessionMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getUeIpSessionMap() const {
  return mpUeIpSessionMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getNextProgRuleMap() const {
  return mpNextProgRuleMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getNextProgRuleIndexMap()
    const {
  return mpNextProgRuleIndexMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getSessionMappingMap()
    const {
  return mpSessionMappingMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpTeidSessionMap = std::make_shared<BPFMap>(mpMaps->getMap("m_teid_session"));
  mpUeIpSessionMap = std::make_shared<BPFMap>(mpMaps->getMap("m_ueip_session"));
  mpNextProgRuleMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_next_rule_prog"));
  mpNextProgRuleIndexMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_next_rule_prog_index"));
  mpSessionMappingMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_session_mapping"));
}

/*---------------------------------------------------------------------------------------------------------------*/
