/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DPDK_WORKER_H_
#define DPDK_WORKER_H_

#include <atomic>

#include "DpdkPipeline.h"
#include "DpdkPort.h"
#include "DpdkSessionTables.h"

/**
 * @struct WorkerAssignment
 * @brief What one lcore is responsible for.
 *
 * Each worker owns exactly one RX queue, and one TX queue on every port, so
 * the fast path never takes a lock and never shares a queue.
 */
struct WorkerAssignment {
  unsigned lcore_id  = 0;
  unsigned reader_id = 0;  ///< RCU reader slot, unique per worker
  uint16_t rx_port_id  = 0;
  uint16_t rx_queue_id = 0;
  PortRole ingress     = PortRole::N3;
  uint16_t tx_queue_id = 0;  ///< This worker's queue, on either port
};

/**
 * @class DpdkWorker
 * @brief The poll loop of one lcore: receive, run the pipeline, transmit.
 *
 * Runs until the datapath clears the shared `running` flag. Each iteration
 * ends with a quiescent-state report, which is what lets the N4 thread free
 * the rule sets it has replaced.
 */
class DpdkWorker {
 public:
  DpdkWorker(
      WorkerAssignment assignment, const DpdkSessionTables& tables,
      const DpdkEgress& to_ran, const DpdkEgress& to_data_network,
      const std::atomic<bool>& running);

  DpdkWorker(const DpdkWorker&) = delete;
  DpdkWorker& operator=(const DpdkWorker&) = delete;

  /// rte_eal_remote_launch entry point; @p argument is a DpdkWorker*.
  static int LaunchTrampoline(void* argument);

  void Run();

  [[nodiscard]] const WorkerAssignment& assignment() const {
    return assignment_;
  }
  [[nodiscard]] const PipelineStats& stats() const { return pipeline_.stats(); }

 private:
  /// Send a batch, freeing whatever the device could not take.
  void Flush(TxBatch& batch, uint16_t port_id);

  WorkerAssignment assignment_;
  const DpdkSessionTables& tables_;
  const DpdkEgress& to_ran_;
  const DpdkEgress& to_data_network_;
  const std::atomic<bool>& running_;
  DpdkPipeline pipeline_;
};

#endif  // DPDK_WORKER_H_
