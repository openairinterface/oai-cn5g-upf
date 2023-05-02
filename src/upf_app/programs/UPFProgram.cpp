#include "UPFProgram.h"
#include <SessionManager.h>
#include <bpf/bpf.h>       // bpf calls
#include <bpf/libbpf.h>    // bpf wrappers
#include <iostream>        // cout
#include <stdexcept>       // exception
#include <utils/LogDefines.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces.h"

#include "upf_config.hpp"
extern upf_config upf_cfg;


UPFProgram::UPFProgram(const std::string& gtpInterface, const std::string& udpInterface)
 : mGTPInterface(gtpInterface), mUDPInterface(udpInterface)
{
  LOG_FUNC();

  __builtin_memset(&gtp_interface, 0, sizeof(struct interface));
  __builtin_memset(&udp_interface, 0, sizeof(struct interface));

  if(mUDPInterface.empty() || mGTPInterface.empty()){
    LOG_ERROR("GTP and/or UDP interface(s) are not defined!");
    throw std::runtime_error("GTP and/or UDP interface(s) are not defined!");
  }

  gtp_interface.if_name = gtpInterface;
  gtp_interface.ipv4_address = upf_cfg.gtpInterface.addr4;
  
  udp_interface.if_name = udpInterface;
  udp_interface.ipv4_address = upf_cfg.udpInterface.addr4;

  LOG_DBG("GTP Interface: %s, IF_NAME: %d, IPv4: %d \n", gtp_interface.if_name, gtp_interface.ipv4_address);
  LOG_DBG("UDP Interface: %s, IF_NAME: %d, IPv4: %d \n", udp_interface.if_name, udp_interface.ipv4_address);
  
  mpLifeCycle = std::make_shared<UPFProgramLifeCycle>(upf_xdp_bpf_c__open, upf_xdp_bpf_c__load, upf_xdp_bpf_c__attach, upf_xdp_bpf_c__destroy);
}


UPFProgram::~UPFProgram()
{
  LOG_FUNC();
}

void UPFProgram::setup()
{
  LOG_FUNC();

  LOG_DBG("Saving Interfaces in Map");
  auto gtpInterface = UserPlaneComponent::getInstance().getGTPInterface();
  auto udpInterface = UserPlaneComponent::getInstance().getUDPInterface();
  
  uint32_t gtpInterfaceIndex = if_nametoindex(gtpInterface.c_str());
  uint32_t udpInterfaceIndex = if_nametoindex(udpInterface.c_str());
  
  mpIfaceMap->update(gtpInterfaceIndex, gtp_interface.ipv4_address, BPF_ANY);
  mpIfaceMap->update(udpInterfaceIndex, udp_interface.ipv4_address, BPF_ANY);
 
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();
  // Entry point interface
  LOG_DBG("Link UDP interface to interface {}", mUDPInterface.c_str())
  mpLifeCycle->link("xdp_entry_point", mUDPInterface.c_str());
  LOG_DBG("Link GTP interface to interface {}", mGTPInterface.c_str())
  mpLifeCycle->link("xdp_entry_point", mGTPInterface.c_str());
}

std::shared_ptr<BPFMaps> UPFProgram::getMaps()
{
  LOG_FUNC();
  return mpMaps;
}

// TODO navarrothiago - check when kill when running.
// It was noted the infinity loop.
void UPFProgram::tearDown()
{
  LOG_FUNC();
  mpLifeCycle->tearDown();
}

void UPFProgram::updateProgramMap(uint32_t key, uint32_t fd)
{
  LOG_FUNC();
  mpTeidSessionMap->update(key, fd, BPF_ANY);
}

void UPFProgram::removeProgramMap(uint32_t key)
{
  LOG_FUNC();
  s32 fd;
  // Remove only if exists.
  if(mpTeidSessionMap->lookup(key, &fd) == 0) {
    mpTeidSessionMap->remove(key);
  }
}

std::shared_ptr<BPFMap> UPFProgram::getTeidSessionMap() const
{
  LOG_FUNC();
  return mpTeidSessionMap;
}

std::shared_ptr<BPFMap> UPFProgram::getUeIpSessionMap() const
{
  LOG_FUNC();
  return mpUeIpSessionMap;
}

std::shared_ptr<BPFMap> UPFProgram::getNextProgRuleMap() const
{
  LOG_FUNC();
  return mpNextProgRuleMap;
}

std::shared_ptr<BPFMap> UPFProgram::getNextProgRuleIndexMap() const
{
  LOG_FUNC();
  return mpNextProgRuleIndexMap;
}

std::shared_ptr<BPFMap> UPFProgram::getIfaceMap() const
{
  LOG_FUNC();
  return mpIfaceMap;
}


void UPFProgram::initializeMaps()
{
  LOG_FUNC();
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpTeidSessionMap = std::make_shared<BPFMap>(mpMaps->getMap("m_teid_session"));
  mpUeIpSessionMap = std::make_shared<BPFMap>(mpMaps->getMap("m_ueip_session"));
  mpNextProgRuleMap = std::make_shared<BPFMap>(mpMaps->getMap("m_next_rule_prog"));
  mpNextProgRuleIndexMap = std::make_shared<BPFMap>(mpMaps->getMap("m_next_rule_prog_index"));
  mpIfaceMap = std::make_shared<BPFMap>(mpMaps->getMap("m_iface"));
}
