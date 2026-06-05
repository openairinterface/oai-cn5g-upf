/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef ETH_BROADCAST_TC_USER_H_
#define ETH_BROADCAST_TC_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <eth_broadcast_tc_kern_skel.h>
#include <wrappers/BPFMap.hpp>
#include <BPFProgram.h>
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

/* ==========================================================================
 * Type alias
 * ========================================================================== */

using EthBroadcastTCProgramLifeCycle =
    ProgramLifeCycle<eth_broadcast_tc_kern_c>;

/* ==========================================================================
 * EthBroadcastTCProgram
 * ========================================================================== */

/**
 * @class EthBroadcastTCProgram
 * @brief Manages the TC-BPF program that fans broadcast / multicast Ethernet
 *        frames out to every active ETH PDU session.
 *
 * TS 23.501 §5.8.2.5.3 — for an Ethernet PDU session, UL frames that are
 * broadcast / multicast must be forwarded to N6 *and* downlinked to every
 * other PDU session.  DL broadcast frames received on N6 (encapsulated by
 * xdp_n6_eth_entry with TEID=0) must be cloned to every active session.
 *
 * The kernel-side BPF program is kernel/tc/eth_broadcast_tc_kern.c
 * (SEC("tc/ingress") handle_broadcast).
 *
 * Attach points:
 *   - N3 (gNB-facing) ingress at INGRESS_BROADCAST_PRIORITY
 *   - N6 (DN-facing)  ingress at INGRESS_BROADCAST_PRIORITY
 *
 * N6 is set to promiscuous mode so the kernel delivers raw Ethernet frames
 * (other than ones addressed to the UPF) into the TC ingress chain.
 *
 * Thread Safety: Not thread-safe. Use from a single thread.
 */
class EthBroadcastTCProgram : public BPFProgram {
 public:
  /**
   * @brief Constructor — initializes the broadcast TC-BPF program.
   *
   * Network configuration is read from upf::g_net_cfg which must be
   * populated by control/Configuration.cpp before the first instance is
   * created.
   *
   * @throws std::runtime_error if skeleton creation fails.
   */
  explicit EthBroadcastTCProgram();

  /**
   * @brief Destructor.
   */
  virtual ~EthBroadcastTCProgram();

  /**
   * @brief Open, load, attach the TC-BPF program and wire its egress
   *        interface map.
   *
   * Populates eth_egress_ifindex_map with:
   *   [DOWNLINK] = if_nametoindex(N3)
   *   [UPLINK]   = if_nametoindex(N6)
   *
   * Sets the N6 interface to promiscuous mode, then attaches
   * handle_broadcast to TC ingress on both N3 and N6.
   *
   * @throws std::runtime_error if interface resolution or TC attach fails.
   */
  void Setup();

  /**
   * @brief Tear the TC-BPF program down (detach + destroy).
   */
  void TearDown();

  /**
   * @brief Get all BPF maps exposed by the skeleton.
   */
  std::shared_ptr<BPFMaps> GetMaps();

  /**
   * @brief Get the underlying libbpf object (post-open).
   *
   * Used by UPF_XDPProgram::Setup() to redirect this program's map symbols
   * to FDs owned by the XDP loaders (bpf_map__reuse_fd), so the broadcast
   * TC program and the ETH XDP programs share the same kernel maps.
   */
  struct bpf_object* GetBpfObject() const;

  /**
   * @brief Get the eth_egress_ifindex_map (slot -> kernel ifindex).
   */
  std::shared_ptr<BPFMap> GetEgressIfindexMap() const;

  /**
   * @brief Get the eth_session_mapping_map (UL TEID -> eth_session_id).
   */
  std::shared_ptr<BPFMap> GetSessionMappingMap() const;

 private:
  /**
   * @brief Validate and apply runtime sizes to maps owned by this program.
   */
  void ConfigureMaps(struct eth_broadcast_tc_kern_c* skel);

  /**
   * @brief Wrap the skeleton maps in BPFMap helpers.
   */
  void InitializeMaps();

  /* Skeleton + lifecycle */
  eth_broadcast_tc_kern_c* skeleton_;
  std::shared_ptr<EthBroadcastTCProgramLifeCycle> lifecycle_;

  /* Map wrappers */
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> egress_ifindex_map_;
  std::shared_ptr<BPFMap> session_mapping_map_;
};

#endif  // ETH_BROADCAST_TC_USER_H_
