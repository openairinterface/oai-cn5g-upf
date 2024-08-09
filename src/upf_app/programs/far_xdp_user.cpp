#include "far_xdp_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>     // bpf calls
#include <bpf/libbpf.h>  // bpf wrappers
#include <iostream>      // cout
#include <stdexcept>     // exception
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_config.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

/*---------------------------------------------------------------------------------------------------------------*/
FARProgram::FARProgram() : BPFProgram() {
  mpLifeCycle = std::make_shared<FARProgramLifeCycle>(
      far_xdp_kernel_c__open, far_xdp_kernel_c__load, far_xdp_kernel_c__attach,
      far_xdp_kernel_c__destroy);
}

/*---------------------------------------------------------------------------------------------------------------*/
FARProgram::~FARProgram() {}

/*---------------------------------------------------------------------------------------------------------------*/
void FARProgram::create_upf_interface_map_entry(e_reference_point s) {
  struct s_interface iface;
  __builtin_memset(&iface, 0, sizeof(s_interface));

  switch (s) {
    case N3_INTERFACE:
      iface.ipv4_address = upf_cfg.n3.addr4.s_addr;
      iface.port         = upf_cfg.n3.port;
      iface.if_name      = (upf_cfg.n3.if_name).c_str();
      getIfaceMap()->update(s, iface, BPF_ANY);
      Logger::upf_app().info("Reference Point N3 Added to m_upf_interface Map");
      break;
    case N6_INTERFACE:
      iface.ipv4_address = upf_cfg.n6.addr4.s_addr;
      iface.port         = upf_cfg.n6.port;
      iface.if_name      = (upf_cfg.n6.if_name).c_str();
      getIfaceMap()->update(s, iface, BPF_ANY);
      Logger::upf_app().info("Reference Point N6 Added to m_upf_interface Map");
      break;
    case N4_INTERFACE:
      iface.ipv4_address = upf_cfg.n4.addr4.s_addr;
      iface.port         = upf_cfg.n4.port;
      iface.if_name      = (upf_cfg.n4.if_name).c_str();
      getIfaceMap()->update(s, iface, BPF_ANY);
      Logger::upf_app().info("Reference Point N4 Added to m_upf_interface Map");
      break;
    case N9_INTERFACE:
      Logger::upf_app().error("Reference Point N9 Not Defined");
      break;
    case N19_INTERFACE:
      Logger::upf_app().error("Reference Point N19 Not Defined");
      break;
    default:
      Logger::upf_app().error("The Reference Point is Not Defined");
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
void FARProgram::setup(uint32_t far_id, uint32_t enforcing_qos) {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  Logger::upf_app().debug("Configure redirect interface");
  auto udpInterface = UserPlaneComponent::getInstance().getUDPInterface();
  auto gtpInterface = UserPlaneComponent::getInstance().getGTPInterface();

  uint32_t udpInterfaceIndex = if_nametoindex(udpInterface.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(gtpInterface.c_str());
  uint32_t uplinkId          = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlinkId        = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  mpEgressInterfaceMap->update(uplinkId, udpInterfaceIndex, BPF_ANY);
  mpEgressInterfaceMap->update(downlinkId, gtpInterfaceIndex, BPF_ANY);
  mpEnforcingQoSMap->update(far_id, enforcing_qos, BPF_ANY);

  Logger::upf_app().debug("Adding Reference Points to m_upf_interface Map:");
  create_upf_interface_map_entry(N3_INTERFACE);
  create_upf_interface_map_entry(N6_INTERFACE);
  create_upf_interface_map_entry(N4_INTERFACE);
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMaps> FARProgram::getMaps() {
  return mpMaps;
}

/*---------------------------------------------------------------------------------------------------------------*/
// TODO: Check when kill when running.
// It was noted the infinity loop.
void FARProgram::tearDown() {
  mpLifeCycle->tearDown();
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> FARProgram::getFARMap() const {
  return mpFARMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> FARProgram::getEgressInterfaceMap() const {
  return mpEgressInterfaceMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
int FARProgram::getFd() const {
  return bpf_program__fd(mpLifeCycle->getBPFSkeleton()->progs.far_entry_point);
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> FARProgram::getArpTableMap() const {
  return mpArpTableMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> FARProgram::getIfaceMap() const {
  return mpUPFIfaceMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> FARProgram::getEnforcingQoSMap() const {
  return mpEnforcingQoSMap;
}
/*---------------------------------------------------------------------------------------------------------------*/
void FARProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpFARMap      = std::make_shared<BPFMap>(mpMaps->getMap("m_far"));
  mpArpTableMap = std::make_shared<BPFMap>(mpMaps->getMap("m_arp_table"));
  mpEgressInterfaceMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_redirect_interfaces"));
  mpUPFIfaceMap = std::make_shared<BPFMap>(mpMaps->getMap("m_upf_interfaces"));
  mpEnforcingQoSMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_enforcing_qos"));
}
/*---------------------------------------------------------------------------------------------------------------*/