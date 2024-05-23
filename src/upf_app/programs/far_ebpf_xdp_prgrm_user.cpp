#include "far_ebpf_xdp_prgrm_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>     // bpf calls
#include <bpf/libbpf.h>  // bpf wrappers
#include <iostream>      // cout
#include <stdexcept>     // exception
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_config.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
void get_mac_address(const char* iface, uint8_t mac[6]) {
  int sockfd;
  struct ifreq ifr;

  // Create a socket to perform ioctl operations
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
  }

  // Clear the ifr structure to avoid issues with residual data
  memset(&ifr, 0, sizeof(struct ifreq));

  // Copy the interface name to the ifr structure
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

  // Perform the ioctl operation to get the MAC address
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
    perror("ioctl");
    close(sockfd);
  }

  // Extract the MAC address from the ifr structure and copy it to mac array
  memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

  // Print the MAC address
  printf(
      "MAC address of %s: %02x:%02x:%02x:%02x:%02x:%02x\n", iface, mac[0],
      mac[1], mac[2], mac[3], mac[4], mac[5]);

  // Close the socket
  close(sockfd);
}

using namespace oai::config;
extern upf_config upf_cfg;

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
void FARProgram::create_upf_interface_map_entry(e_reference_point s) {
  struct s_interface iface;
  __builtin_memset(&iface, 0, sizeof(s_interface));

  switch (s) {
    case N3_INTERFACE:
      iface.ipv4_address = upf_cfg.n3.addr4.s_addr;
      iface.port         = upf_cfg.n3.port;
      iface.if_name      = (upf_cfg.n3.if_name).c_str();
      get_mac_address(iface.if_name, iface.mac_address);
      getIfaceMap()->update(s, iface, BPF_ANY);
      Logger::upf_app().info("Reference Point N3 Added to m_upf_interface Map");
      break;
    case N6_INTERFACE:
      iface.ipv4_address = upf_cfg.n6.addr4.s_addr;
      iface.port         = upf_cfg.n6.port;
      iface.if_name      = (upf_cfg.n6.if_name).c_str();
      get_mac_address(iface.if_name, iface.mac_address);
      getIfaceMap()->update(s, iface, BPF_ANY);
      Logger::upf_app().info("Reference Point N6 Added to m_upf_interface Map");
      break;
    case N4_INTERFACE:
      iface.ipv4_address = upf_cfg.n4.addr4.s_addr;
      iface.port         = upf_cfg.n4.port;
      iface.if_name      = (upf_cfg.n4.if_name).c_str();
      get_mac_address(iface.if_name, iface.mac_address);
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

/*****************************************************************************************************************/
void FARProgram::setup() {
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

  Logger::upf_app().debug("Adding Reference Points to m_upf_interface Map:");
  create_upf_interface_map_entry(N3_INTERFACE);
  create_upf_interface_map_entry(N6_INTERFACE);
  create_upf_interface_map_entry(N4_INTERFACE);
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
std::shared_ptr<BPFMap> FARProgram::getIfaceMap() const {
  return mpUPFIfaceMap;
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
  mpUPFIfaceMap = std::make_shared<BPFMap>(mpMaps->getMap("m_upf_interfaces"));
}
/*****************************************************************************************************************/