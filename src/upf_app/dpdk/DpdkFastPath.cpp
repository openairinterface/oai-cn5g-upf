/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DpdkFastPath.h"

#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_version.h>

#include <atomic>
#include <stdexcept>
#include <vector>

#include "DpdkPort.h"
#include "DpdkSessionTables.h"
#include "DpdkWorker.h"
#include "logger.hpp"
#include "upf_config.hpp"

extern oai::config::upf_config upf_cfg;

/**
 * @struct DpdkFastPath::Impl
 * @brief The DPDK-side state, kept out of the header so no translation unit
 *        has to include both the DPDK and the PFCP headers.
 */
struct DpdkFastPath::Impl {
  explicit Impl(DpdkSessionTables& session_tables) : tables(session_tables) {}

  DpdkSessionTables& tables;
  /// One entry in single-port mode, two otherwise.
  std::vector<std::unique_ptr<DpdkPort>> ports;
  DpdkEgress to_ran{};
  DpdkEgress to_data_network{};
  std::vector<std::unique_ptr<DpdkWorker>> workers;
  std::atomic<bool> running{false};
  bool is_setup = false;

  void SetupPorts();
  void LaunchWorkers();
};

//------------------------------------------------------------------------------
void DpdkFastPath::Impl::SetupPorts() {
  const auto& dpdk = upf_cfg.dpdk;

  if (dpdk.is_single_port()) {
    // One device carries both interfaces; the pipeline splits the directions
    // per packet. Its queue and lcore settings come from the n3 entry.
    ports.push_back(std::make_unique<DpdkPort>(PortRole::Shared, dpdk.n3));
    Logger::upf_app().info(
        "DPDK: single-port mode on %s — the n6 queue and lcore settings are "
        "ignored",
        dpdk.n3.pci_address.c_str());
  } else {
    ports.push_back(std::make_unique<DpdkPort>(PortRole::N3, dpdk.n3));
    ports.push_back(std::make_unique<DpdkPort>(PortRole::N6, dpdk.n6));
  }

  // Every worker gets its own TX queue on every port, so none of them share.
  uint16_t total_workers = 0;
  for (const auto& port : ports) {
    total_workers += static_cast<uint16_t>(port->lcores().size());
  }

  for (auto& port : ports) {
    port->Start(dpdk, total_workers);
  }

  // Wire the egress targets. In single-port mode both point at the one port
  // but keep their own next hop.
  to_ran.port         = ports.front().get();
  to_ran.has_next_hop = ParseMacAddress(dpdk.n3.next_hop_mac, to_ran.next_hop);

  to_data_network.port =
      dpdk.is_single_port() ? ports.front().get() : ports.back().get();
  to_data_network.has_next_hop =
      ParseMacAddress(dpdk.n6.next_hop_mac, to_data_network.next_hop);

  const std::pair<const char*, const DpdkEgress*> egresses[] = {
      {"N3", &to_ran}, {"N6", &to_data_network}};
  for (const auto& [name, egress] : egresses) {
    if (egress->has_next_hop) {
      Logger::upf_app().info(
          "DPDK: %s next hop %s on port %u", name,
          MacToString(egress->next_hop).c_str(), egress->port_id());
    } else {
      Logger::upf_app().warn(
          "DPDK: no next_hop_mac configured for %s; that direction cannot "
          "forward until ARP resolution is implemented",
          name);
    }
  }
}

//------------------------------------------------------------------------------
void DpdkFastPath::Impl::LaunchWorkers() {
  unsigned reader_id   = 0;
  uint16_t tx_queue_id = 0;

  for (const auto& port : ports) {
    uint16_t rx_queue_id = 0;
    for (unsigned lcore : port->lcores()) {
      if (!rte_lcore_is_enabled(lcore)) {
        throw std::runtime_error(
            "DPDK: lcore " + std::to_string(lcore) +
            " polls a port but is not in the EAL core list");
      }
      if (lcore == rte_get_main_lcore()) {
        throw std::runtime_error(
            "DPDK: lcore " + std::to_string(lcore) +
            " is the main lcore and cannot poll a port");
      }

      WorkerAssignment assignment;
      assignment.lcore_id    = lcore;
      assignment.reader_id   = reader_id++;
      assignment.rx_port_id  = port->id();
      assignment.rx_queue_id = rx_queue_id++;
      assignment.ingress     = port->role();
      assignment.tx_queue_id = tx_queue_id++;

      workers.push_back(std::make_unique<DpdkWorker>(
          assignment, tables, to_ran, to_data_network, running));
    }
  }

  running.store(true, std::memory_order_relaxed);

  for (auto& worker : workers) {
    const unsigned lcore = worker->assignment().lcore_id;
    if (rte_eal_remote_launch(
            DpdkWorker::LaunchTrampoline, worker.get(), lcore) != 0) {
      running.store(false, std::memory_order_relaxed);
      rte_eal_mp_wait_lcore();
      throw std::runtime_error(
          "DPDK: cannot launch the worker on lcore " + std::to_string(lcore));
    }
  }

  Logger::upf_app().info(
      "DPDK: %zu worker(s) running on %zu port(s)", workers.size(),
      ports.size());
}

//------------------------------------------------------------------------------
DpdkFastPath::DpdkFastPath(DpdkSessionTables& tables)
    : impl_(std::make_unique<Impl>(tables)) {}

//------------------------------------------------------------------------------
DpdkFastPath::~DpdkFastPath() {
  TearDown();
}

//------------------------------------------------------------------------------
void DpdkFastPath::Setup(uint32_t max_sessions) {
  Logger::upf_app().info("DPDK: starting the fast path (%s)", rte_version());

  impl_->SetupPorts();

  // The tables must be ready, and sized for exactly as many readers as there
  // are workers, before any worker starts polling.
  uint32_t reader_count = 0;
  for (const auto& port : impl_->ports) {
    reader_count += static_cast<uint32_t>(port->lcores().size());
  }
  impl_->tables.Setup(max_sessions, reader_count);

  impl_->LaunchWorkers();
  impl_->is_setup = true;
}

//------------------------------------------------------------------------------
void DpdkFastPath::LogStatistics() const {
  for (const auto& port : impl_->ports) {
    port->LogStatistics();
  }
  for (const auto& worker : impl_->workers) {
    const PipelineStats& stats = worker->stats();
    Logger::upf_app().info(
        "DPDK: lcore %u — rx %lu, uplink %lu, downlink %lu, dropped %lu",
        worker->assignment().lcore_id, stats.received, stats.uplink_forwarded,
        stats.downlink_forwarded,
        stats.dropped_malformed + stats.dropped_no_session +
            stats.dropped_no_rule + stats.dropped_action +
            stats.dropped_no_room + stats.dropped_no_next_hop);
  }
}

//------------------------------------------------------------------------------
void DpdkFastPath::TearDown() {
  if (!impl_ || !impl_->is_setup) return;

  // Stop the workers before anything they read goes away.
  impl_->running.store(false, std::memory_order_relaxed);
  rte_eal_mp_wait_lcore();

  LogStatistics();

  impl_->workers.clear();
  for (auto& port : impl_->ports) {
    port->Stop();
  }
  impl_->ports.clear();
  impl_->is_setup = false;

  Logger::upf_app().info("DPDK: fast path stopped");
}
