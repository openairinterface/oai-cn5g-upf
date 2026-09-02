/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "eth_broadcast_tc_user.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <errno.h>
#include <cstring>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces_types.h"
#include "logger.hpp"
#include "helpers/GetNicInformation.hpp"
#include "utils/net_utils.hpp"
#include "utils/bpf_utils.hpp"

using namespace oai::utils::bpf;
using namespace oai::utils::net;

/* -------------------------------------------------------------------------- */
void EthBroadcastTCProgram::ConfigureMaps(
    struct eth_broadcast_tc_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in ConfigureMaps");
    return;
  }

  const uint32_t max_ifaces   = upf::GetMaxUpfInterfaces();
  const uint32_t max_redirect = upf::GetMaxUpfRedirectInterfaces();
  const uint32_t max_sessions = upf::GetMaxPduSessions();

  int num_ifaces = CountAvailableInterfaces();
  if (max_ifaces > static_cast<uint32_t>(num_ifaces)) {
    Logger::upf_app().warn(
        "Configured max_upf_interfaces (%u) exceeds available system "
        "interfaces (%d). Clamping to %d.",
        max_ifaces, num_ifaces, num_ifaces);
  }

  if (max_redirect > max_ifaces) {
    Logger::upf_app().error(
        "Invalid config: max_upf_redirect_interfaces (%u) cannot exceed "
        "max_upf_interfaces (%u).",
        max_redirect, max_ifaces);
    throw std::runtime_error(
        "Invalid UPF configuration (redirect > interfaces)");
  }

  bool ok = true;

  /* eth_egress_ifindex_map: DEVMAP sized to MAX_UPF_REDIRECT_INTERFACES */
  ok &= ConfigureMapMaxEntries(
      skel->maps.eth_egress_ifindex_map, "eth_egress_ifindex_map",
      max_redirect);

  /* eth_session_mapping_map: shared with the XDP loaders via
   * bpf_map__reuse_fd() at Setup() time. Size it to MAX_PDU_SESSIONS so
   * that, if for some reason it is *not* reused (first-loader wins),
   * the standalone instance still has enough room. */
  ok &= ConfigureMapMaxEntries(
      skel->maps.eth_session_mapping_map, "eth_session_mapping_map",
      max_sessions);

  if (!ok) {
    Logger::upf_app().error(
        "One or more BPF map configurations failed for "
        "EthBroadcastTCProgram.");
    throw std::runtime_error("EthBroadcastTCProgram map configuration failed");
  }
}

/* -------------------------------------------------------------------------- */
EthBroadcastTCProgram::EthBroadcastTCProgram() : BPFProgram() {
  Logger::upf_app().debug("Initializing ETH Broadcast TC BPF program ...");

  auto open_fn = [this]() -> eth_broadcast_tc_kern_c* {
    struct eth_broadcast_tc_kern_c* skel = eth_broadcast_tc_kern_c__open();
    if (!skel) {
      Logger::upf_app().error("Failed to open eth_broadcast_tc skeleton");
      return nullptr;
    }
    this->ConfigureMaps(skel);
    // Store skeleton pointer -- available from this point onwards. Without
    // this, GetBpfObject() reads an indeterminate skeleton_ and
    // ShareMapsOwned() silently skips sharing eth_session_mapping_map.
    skeleton_ = skel;
    return skel;
  };

  lifecycle_ = std::make_shared<EthBroadcastTCProgramLifeCycle>(
      open_fn,
      /* load    */ eth_broadcast_tc_kern_c__load,
      /* attach  */ eth_broadcast_tc_kern_c__attach,
      /* destroy */ eth_broadcast_tc_kern_c__destroy, "EthBroadcastTCProgram");
}

/* -------------------------------------------------------------------------- */
EthBroadcastTCProgram::~EthBroadcastTCProgram() {}

/* -------------------------------------------------------------------------- */
void EthBroadcastTCProgram::Setup() {
  const std::string udp_iface = upf::GetN6Iface(); /* DN-facing */
  const std::string gtp_iface = upf::GetN3Iface(); /* gNB-facing */

  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
  lifecycle_->attach();

  uint32_t udp_if_index = if_nametoindex(udp_iface.c_str());
  uint32_t gtp_if_index = if_nametoindex(gtp_iface.c_str());

  if (udp_if_index == 0 || gtp_if_index == 0) {
    Logger::upf_app().error(
        "EthBroadcastTC: failed to resolve interface indices (N3=%s, N6=%s)",
        gtp_iface.c_str(), udp_iface.c_str());
    throw std::runtime_error("Invalid network interface index");
  }

  uint32_t uplink_id   = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlink_id = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  egress_ifindex_map_->Update(uplink_id, udp_if_index, BPF_ANY);
  egress_ifindex_map_->Update(downlink_id, gtp_if_index, BPF_ANY);

  Logger::upf_app().info(
      "EthBroadcastTC: egress map populated (DL=%s/ifindex=%u, "
      "UL=%s/ifindex=%u)",
      gtp_iface.c_str(), gtp_if_index, udp_iface.c_str(), udp_if_index);

  /* ETH PDU sessions require the N6 (DN-facing) NIC to accept frames
   * addressed to MACs other than its own — enable promiscuous mode. */
  std::string cmd = fmt::format("ip link set dev {} promisc on", udp_iface);
  int rc          = system(cmd.c_str());
  if (rc != 0) {
    Logger::upf_app().error(
        "EthBroadcastTC: failed to set %s to promiscuous mode (rc=%d, "
        "errno=%s)",
        udp_iface.c_str(), rc, std::strerror(errno));
  }

  Logger::upf_app().info(
      "EthBroadcastTC: attaching handle_broadcast to N3 (%s) ingress",
      gtp_iface.c_str());
  lifecycle_->tcAttachIngress(
      "handle_broadcast", gtp_iface.c_str(), INGRESS_BROADCAST_PRIORITY);

  Logger::upf_app().info(
      "EthBroadcastTC: attaching handle_broadcast to N6 (%s) ingress",
      udp_iface.c_str());
  lifecycle_->tcAttachIngress(
      "handle_broadcast", udp_iface.c_str(), INGRESS_BROADCAST_PRIORITY);
}

/* -------------------------------------------------------------------------- */
void EthBroadcastTCProgram::TearDown() {
  lifecycle_->tearDown();
}

/* -------------------------------------------------------------------------- */
std::shared_ptr<BPFMaps> EthBroadcastTCProgram::GetMaps() {
  return maps_;
}

/* -------------------------------------------------------------------------- */
struct bpf_object* EthBroadcastTCProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

/* -------------------------------------------------------------------------- */
std::shared_ptr<BPFMap> EthBroadcastTCProgram::GetEgressIfindexMap() const {
  return egress_ifindex_map_;
}

/* -------------------------------------------------------------------------- */
std::shared_ptr<BPFMap> EthBroadcastTCProgram::GetSessionMappingMap() const {
  return session_mapping_map_;
}

/* -------------------------------------------------------------------------- */
void EthBroadcastTCProgram::InitializeMaps() {
  maps_ = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);

  egress_ifindex_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("eth_egress_ifindex_map"));
  session_mapping_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("eth_session_mapping_map"));
}
