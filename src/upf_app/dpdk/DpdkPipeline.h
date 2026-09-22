/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DPDK_PIPELINE_H_
#define DPDK_PIPELINE_H_

#include <rte_ether.h>
#include <rte_gtp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <cstdint>

#include "DpdkPort.h"
#include "DpdkSessionTables.h"

/// Packets collected for one egress port during a burst.
struct TxBatch {
  static constexpr uint16_t kCapacity = 64;
  rte_mbuf* packets[kCapacity]        = {};
  uint16_t count                      = 0;

  bool Add(rte_mbuf* packet) {
    if (count >= kCapacity) return false;
    packets[count++] = packet;
    return true;
  }
  void Clear() { count = 0; }
};

/**
 * @struct PipelineStats
 * @brief Per-lcore counters. Owned by one lcore, so no atomics needed.
 */
struct PipelineStats {
  uint64_t received          = 0;
  uint64_t uplink_forwarded  = 0;
  uint64_t downlink_forwarded = 0;
  uint64_t dropped_malformed = 0;  ///< Too short, or not IPv4/GTP-U
  uint64_t dropped_no_session = 0;  ///< No PFCP session for TEID / UE IP
  uint64_t dropped_no_rule   = 0;  ///< No matching PDR, or its FAR is missing
  uint64_t dropped_action    = 0;  ///< FAR says drop, or the QER gate is shut
  uint64_t dropped_no_room   = 0;  ///< Not enough head room to encapsulate
  uint64_t dropped_no_next_hop = 0;  ///< Egress next-hop MAC not known yet
  uint64_t arp_replies       = 0;  ///< ARP requests answered
  uint64_t gtp_echo_replies  = 0;  ///< GTP-U Echo Requests answered
  uint64_t punted            = 0;  ///< Control traffic we do not handle
};

/**
 * @class DpdkPipeline
 * @brief The per-packet work: classify, find the session, pick the PDR, apply
 *        the QER gate and the FAR, and hand the packet to an egress batch.
 *
 * Uplink  (N3): GTP-U in → decapsulate → out on N6 (TS 29.281 §5.1).
 * Downlink (N6): UE-addressed IP in → encapsulate with the FAR's Outer Header
 *                Creation → out on N3, carrying the PDU Session Container
 *                with the QFI (TS 38.415), which is what the eBPF flavour
 *                emits too.
 *
 * One instance per lcore: it holds no mutable shared state, reads the session
 * tables lock-free, and only ever touches its own PipelineStats.
 */
class DpdkPipeline {
 public:
  DpdkPipeline(
      const DpdkSessionTables& tables, const DpdkEgress& to_ran,
      const DpdkEgress& to_data_network);

  /**
   * @brief Process one received burst.
   *
   * Every packet ends up either in one of the batches or freed.
   *
   * @param ingress Role of the port the burst came from. With a single shared
   *        port this is PortRole::Shared and the direction is decided per
   *        packet.
   */
  void ProcessBurst(
      PortRole ingress, rte_mbuf** packets, uint16_t count, TxBatch& to_n3,
      TxBatch& to_n6);

  [[nodiscard]] const PipelineStats& stats() const { return stats_; }

 private:
  /// Where a processed packet should go.
  enum class Egress : uint8_t { Drop, ToN3, ToN6 };

  Egress ProcessPacket(rte_mbuf* packet, PortRole ingress);
  Egress HandleUplink(rte_mbuf* packet, rte_ipv4_hdr* outer_ip);
  Egress HandleDownlink(rte_mbuf* packet, rte_ipv4_hdr* inner_ip);

  /**
   * @brief Answer an ARP request for one of our own addresses.
   *
   * With the NIC taken from the kernel there is no host stack to do this, and
   * peers cannot reach the UPF until it replies itself.
   */
  Egress HandleArp(
      rte_mbuf* packet, rte_ether_hdr* ethernet, PortRole ingress);

  /**
   * @brief Answer a GTP-U Echo Request (TS 29.281 §7.2.2).
   *
   * gNBs probe the tunnel endpoint periodically and tear the tunnel down when
   * nothing answers.
   */
  Egress HandleGtpEcho(
      rte_mbuf* packet, rte_ether_hdr* ethernet, rte_ipv4_hdr* outer_ip,
      const rte_gtp_hdr* request);

  /// First PDR of @p candidates whose TEID matches (already precedence-sorted).
  static const struct pfcp_pdr* MatchUplinkPdr(
      const DpdkSessionRules& rules, uint32_t teid);
  /// First downlink PDR; the UE IP already selected the session.
  static const struct pfcp_pdr* MatchDownlinkPdr(
      const DpdkSessionRules& rules);

  /// False when the QER shuts the gate for this direction (§8.2.7).
  static bool GateIsOpen(
      const DpdkSessionRules& rules, const struct pfcp_pdr& pdr, bool uplink);

  const DpdkSessionTables& tables_;
  const DpdkEgress& to_ran_;            ///< N3 side: towards the gNB
  const DpdkEgress& to_data_network_;   ///< N6 side: towards the DN gateway
  uint32_t n3_local_ip_;  ///< Source address of the GTP-U tunnels we build
  uint32_t n6_local_ip_;  ///< Our address on the data network side
  PipelineStats stats_;
};

#endif  // DPDK_PIPELINE_H_
