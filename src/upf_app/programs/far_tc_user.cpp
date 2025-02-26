#include "far_tc_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>  // bpf calls
#include <iostream>   // cout
#include <stdexcept>  // exception
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include <chrono>
#include <iostream>
#include "interfaces.h"
#include "logger.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#ifndef UDP_INTERFACE
#define UDP_INTERFACE UserPlaneComponent::getInstance().getUDPInterface()
#endif  // UDP_INTERFACE

#ifndef GTP_INTERFACE
#define GTP_INTERFACE UserPlaneComponent::getInstance().getGTPInterface()
#endif  // GTP_INTERFACE

static int verbose = 1;

#define EGRESS_HANDLE 0x1
#define EGRESS_PRIORITY 0xC02F

#define INGRESS_HANDLE 0x1
#define INGRESS_PRIORITY 0xC02F

/*---------------------------------------------------------------------------------------------------------------*/
FARTCProgram::FARTCProgram() : BPFProgram() {
  mpLifeCycle = std::make_shared<FARTCProgramLifeCycle>(
      far_tc_kernel_c__open, far_tc_kernel_c__load, far_tc_kernel_c__attach,
      far_tc_kernel_c__destroy);
}

/*---------------------------------------------------------------------------------------------------------------*/
FARTCProgram::~FARTCProgram() {}

/*---------------------------------------------------------------------------------------------------------------*/
void FARTCProgram::setup() {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  struct far_tc_kernel_c* obj = NULL;

  std::string cmd = {};
  int rc          = 0;
  int if_index    = 0;

  uint32_t udpInterfaceIndex = if_nametoindex(UDP_INTERFACE.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(GTP_INTERFACE.c_str());
  uint32_t uplinkId          = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlinkId        = static_cast<uint32_t>(FlowDirection::DOWNLINK);
  mpEgressInterfaceMap->update(uplinkId, udpInterfaceIndex, BPF_ANY);
  mpEgressInterfaceMap->update(downlinkId, gtpInterfaceIndex, BPF_ANY);

  Logger::upf_app().info("Attach Section far_tc_kernel to gtp interface");
  mpLifeCycle->tcAttachIngress("handle_broadcast", GTP_INTERFACE.c_str(), INGRESS_BROADCAST_PRIORITY);

  Logger::upf_app().info("Attach Sesction far_tc_kernel to udp interface");
  mpLifeCycle->tcAttachIngress("handle_broadcast", UDP_INTERFACE.c_str(), INGRESS_BROADCAST_PRIORITY);
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMaps> FARTCProgram::getMaps() {
  return mpMaps;
}

/*---------------------------------------------------------------------------------------------------------------*/
// TODO: Check when kill when running.
// It was noted the infinity loop.
void FARTCProgram::tearDown() {
  mpLifeCycle->tearDown();
}

std::shared_ptr<BPFMap> FARTCProgram::getMacPduSessionMap()
    const {
  return mpMacPduSessionMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> FARTCProgram::getEgressInterfaceMap() const {
  return mpEgressInterfaceMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
void FARTCProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpMacPduSessionMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_mac_pdu_session"));
  mpEgressInterfaceMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_egress_ifindex"));
}
