#include "far_ebpf_xdp_prgrm_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>     // bpf calls
#include <bpf/libbpf.h>  // bpf wrappers
#include <iostream>      // cout
#include <stdexcept>     // exception
// // #include <utils/LogDefines.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"

/*****************************************************************************************************************/
FARProgram::FARProgram() : BPFProgram() {
  mpLifeCycle = std::make_shared<FARProgramLifeCycle>(
      far_ebpf_xdp_prgrm_kernel_c__open, far_ebpf_xdp_prgrm_kernel_c__load,
      far_ebpf_xdp_prgrm_kernel_c__attach,
      far_ebpf_xdp_prgrm_kernel_c__destroy);
}

/*****************************************************************************************************************/
FARProgram::~FARProgram() {}

/*****************************************************************************************************************/
void FARProgram::setup() {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  // LOG_DBG("Configure redirect interface");
  Logger::upf_app().debug("Configure redirect interface");
  auto udpInterface = UserPlaneComponent::getInstance().getUDPInterface();
  auto gtpInterface = UserPlaneComponent::getInstance().getGTPInterface();
  uint32_t udpInterfaceIndex = if_nametoindex(udpInterface.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(gtpInterface.c_str());
  uint32_t uplinkId          = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlinkId        = static_cast<uint32_t>(FlowDirection::DOWNLINK);
  mpEgressInterfaceMap->update(uplinkId, udpInterfaceIndex, BPF_ANY);
  mpEgressInterfaceMap->update(downlinkId, gtpInterfaceIndex, BPF_ANY);
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMaps> FARProgram::getMaps() {
  return mpMaps;
}

/*****************************************************************************************************************/
// TODO: Check when kill when running.
// It was noted the infinity loop.
void FARProgram::tearDown() {
  mpLifeCycle->tearDown();
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> FARProgram::getFARMap() const {
  return mpFARMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> FARProgram::getEgressInterfaceMap() const {
  return mpEgressInterfaceMap;
}

/*****************************************************************************************************************/
int FARProgram::getFd() const {
  return bpf_program__fd(mpLifeCycle->getBPFSkeleton()->progs.far_entry_point);
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> FARProgram::getArpTableMap() const {
  return mpArpTableMap;
}

/*****************************************************************************************************************/
void FARProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpFARMap      = std::make_shared<BPFMap>(mpMaps->getMap("m_far"));
  mpArpTableMap = std::make_shared<BPFMap>(mpMaps->getMap("m_arp_table"));
  mpEgressInterfaceMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_redirect_interfaces"));
}
/*****************************************************************************************************************/