#include "pfcp_session_pdr_lookup_xdp_user.h"
#include <pfcp_session_lookup_xdp_user.h>
#include <bpf/bpf.h>       // bpf calls
#include <bpf/libbpf.h>    // bpf wrappers
#include <sys/resource.h>  // rlimit
#include <net/if.h>        // if_nametoindex
#include <wrappers/BPFMaps.h>
#include <wrappers/BPFMap.hpp>

/*---------------------------------------------------------------------------------------------------------------*/
PFCP_Session_PDR_LookupProgram::PFCP_Session_PDR_LookupProgram(
    const std::string& gtpInterface, const std::string& udpInterface)
    : mGTPInterface(gtpInterface), mUDPInterface(udpInterface) {
  mpLifeCycle = std::make_shared<PFCP_Session_PDR_LookupProgramLifeCycle>(
      pfcp_session_pdr_lookup_xdp_kernel_c__open,
      pfcp_session_pdr_lookup_xdp_kernel_c__load,
      pfcp_session_pdr_lookup_xdp_kernel_c__attach,
      pfcp_session_pdr_lookup_xdp_kernel_c__destroy);
}

/*---------------------------------------------------------------------------------------------------------------*/
PFCP_Session_PDR_LookupProgram::~PFCP_Session_PDR_LookupProgram() {}

/*---------------------------------------------------------------------------------------------------------------*/
// TODO: Pass configuration throught args.
void PFCP_Session_PDR_LookupProgram::setup() {
  mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();
}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_PDR_LookupProgram::tearDown() {
  mpLifeCycle->tearDown();
}

/*---------------------------------------------------------------------------------------------------------------*/
int PFCP_Session_PDR_LookupProgram::getUplinkFileDescriptor() const {
  return bpf_program__fd(
      mpLifeCycle->getBPFSkeleton()->progs.uplink_entry_point);
}

/*---------------------------------------------------------------------------------------------------------------*/
int PFCP_Session_PDR_LookupProgram::getDownlinkFileDescriptor() const {
  return bpf_program__fd(
      mpLifeCycle->getBPFSkeleton()->progs.downlink_entry_point);
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getFARMap() const {
  return mpFARMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getUplinkPDRsMap()
    const {
  return mpUplinkPDRsMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getDownlinkPDRsMap()
    const {
  return mpDownlinkPDRsMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getCounterMap() const {
  return mpCounterMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getEgressInterfaceMap()
    const {
  return mpEgressInterfaceMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getArpTableMap() const {
  return mpArpTableMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_PDR_LookupProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  // Initialize maps.
  mpFARMap          = std::make_shared<BPFMap>(mpMaps->getMap("m_fars"));
  mpUplinkPDRsMap   = std::make_shared<BPFMap>(mpMaps->getMap("m_teid_pdr"));
  mpDownlinkPDRsMap = std::make_shared<BPFMap>(mpMaps->getMap("m_ueip_pdr"));
  mpCounterMap      = std::make_shared<BPFMap>(mpMaps->getMap("mc_stats"));
  mpEgressInterfaceMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_redirect_interfaces"));
  mpArpTableMap = std::make_shared<BPFMap>(mpMaps->getMap("m_arp_table"));
}
/*---------------------------------------------------------------------------------------------------------------*/