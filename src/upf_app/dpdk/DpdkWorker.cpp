/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DpdkWorker.h"

#include <rte_ethdev.h>
#include <rte_lcore.h>

#include "logger.hpp"

namespace {
/// Packets pulled from a queue per poll.
constexpr uint16_t kRxBurstSize = 32;
static_assert(
    kRxBurstSize <= TxBatch::kCapacity,
    "a single RX burst must fit in one TX batch");
}  // namespace

//------------------------------------------------------------------------------
DpdkWorker::DpdkWorker(
    WorkerAssignment assignment, const DpdkSessionTables& tables,
    const DpdkEgress& to_ran, const DpdkEgress& to_data_network,
    const std::atomic<bool>& running)
    : assignment_(assignment),
      tables_(tables),
      to_ran_(to_ran),
      to_data_network_(to_data_network),
      running_(running),
      pipeline_(tables, to_ran, to_data_network) {}

//------------------------------------------------------------------------------
int DpdkWorker::LaunchTrampoline(void* argument) {
  static_cast<DpdkWorker*>(argument)->Run();
  return 0;
}

//------------------------------------------------------------------------------
void DpdkWorker::Run() {
  Logger::upf_app().info(
      "DPDK: lcore %u polling %s port %u queue %u (TX queue %u)",
      assignment_.lcore_id, ToString(assignment_.ingress),
      assignment_.rx_port_id, assignment_.rx_queue_id,
      assignment_.tx_queue_id);

  // From here on this lcore is a table reader.
  tables_.RegisterReader(assignment_.reader_id);

  rte_mbuf* burst[kRxBurstSize];
  TxBatch to_ran;
  TxBatch to_data_network;

  while (running_.load(std::memory_order_relaxed)) {
    const uint16_t received = rte_eth_rx_burst(
        assignment_.rx_port_id, assignment_.rx_queue_id, burst, kRxBurstSize);

    if (received != 0) {
      to_ran.Clear();
      to_data_network.Clear();

      pipeline_.ProcessBurst(
          assignment_.ingress, burst, received, to_ran, to_data_network);

      Flush(to_ran, to_ran_.port_id());
      Flush(to_data_network, to_data_network_.port_id());
    }

    // No rule set is referenced at this point, so a writer may reclaim.
    tables_.ReportQuiescent(assignment_.reader_id);
  }

  // Let go of the tables before this lcore disappears.
  tables_.UnregisterReader(assignment_.reader_id);

  Logger::upf_app().info(
      "DPDK: lcore %u stopped — rx %lu, uplink %lu, downlink %lu, arp %lu, "
      "gtp echo %lu, dropped (malformed %lu, no session %lu, no rule %lu, "
      "action %lu, no room %lu, no next hop %lu), punted %lu",
      assignment_.lcore_id, stats().received, stats().uplink_forwarded,
      stats().downlink_forwarded, stats().arp_replies,
      stats().gtp_echo_replies, stats().dropped_malformed,
      stats().dropped_no_session, stats().dropped_no_rule,
      stats().dropped_action, stats().dropped_no_room,
      stats().dropped_no_next_hop, stats().punted);
}

//------------------------------------------------------------------------------
void DpdkWorker::Flush(TxBatch& batch, uint16_t port_id) {
  if (batch.count == 0) return;

  const uint16_t sent = rte_eth_tx_burst(
      port_id, assignment_.tx_queue_id, batch.packets, batch.count);

  // The ring was full: those packets are ours to free.
  for (uint16_t index = sent; index < batch.count; ++index) {
    rte_pktmbuf_free(batch.packets[index]);
  }
  batch.Clear();
}
