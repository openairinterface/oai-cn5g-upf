/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef I_SESSION_REGISTRY_H_
#define I_SESSION_REGISTRY_H_

#include <cstdint>
#include <memory>

#include "3gpp_29.244.h"

namespace pfcp {
class pfcp_pdr;
}  // namespace pfcp

/**
 * @class ISessionRegistry
 * @brief Everything the PFCP session model needs from a datapath flavour.
 *
 * pfcp::pfcp_session holds the 3GPP session state and parses the Create/Update
 * PDR IEs; it does not know which flavour runs underneath. The few operations
 * that are inherently flavour-specific — allocating an N3 F-TEID and keeping
 * the uplink/downlink lookup entries — go through this interface.
 *
 * Implemented by:
 *   - pfcp_switch      — simple-switch and (for now) eBPF flavours
 *   - DpdkSessionStore — DPDK flavour
 *
 * Called from the N4 (ITTI) thread while a session is created, modified or
 * deleted. A detached session copy (a snapshot handed to a datapath backend)
 * carries no registry and performs no registration at all.
 *
 * @see 3GPP TS 29.244 §7.5.2.2 (Create PDR), §8.2.3 (F-TEID)
 */
class ISessionRegistry {
 public:
  virtual ~ISessionRegistry() = default;

  /// Allocate a local N3 F-TEID for an uplink PDR whose CHOOSE flag is set.
  virtual pfcp::fteid_t AllocateN3Fteid() = 0;

  /**
   * @brief Make an uplink (ACCESS) PDR reachable by its N3 TEID.
   * @param pdr   PDR to register.
   * @param fteid F-TEID the PDR was allocated / assigned.
   * @param cause Set to a 3GPP cause value when registration fails.
   * @return true on success.
   */
  virtual bool RegisterUplinkPdr(
      std::shared_ptr<pfcp::pfcp_pdr>& pdr, const pfcp::fteid_t& fteid,
      uint8_t& cause) = 0;

  /**
   * @brief Make a downlink (CORE) PDR reachable by UE IPv4 address.
   * @param ue_ipv4_hbo UE IPv4 address in host byte order.
   */
  virtual void RegisterDownlinkPdr(
      uint32_t ue_ipv4_hbo, std::shared_ptr<pfcp::pfcp_pdr>& pdr) = 0;

  /// Drop the uplink lookup entries of an N3 TEID.
  virtual void UnregisterUplinkPdr(uint32_t teid) = 0;

  /// Drop the downlink lookup entries of a UE IPv4 address (host byte order).
  virtual void UnregisterDownlinkPdr(uint32_t ue_ipv4_hbo) = 0;
};

#endif  // I_SESSION_REGISTRY_H_
