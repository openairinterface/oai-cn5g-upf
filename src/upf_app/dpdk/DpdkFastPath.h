/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DPDK_FAST_PATH_H_
#define DPDK_FAST_PATH_H_

#include <cstdint>
#include <memory>

class DpdkSessionTables;

/**
 * @class DpdkFastPath
 * @brief Everything that moves packets: the ports, the mbuf pools and the
 *        lcore workers.
 *
 * Deliberately DPDK-free in this header. The DPDK headers reach netinet/ip.h
 * while the PFCP session model reaches linux/ip.h, and the two define
 * struct iphdr differently, so no translation unit may include both. Keeping
 * the implementation behind this interface lets DpdkDatapath handle N4
 * messages without ever seeing a DPDK header.
 */
class DpdkFastPath {
 public:
  /// @param tables Lookup tables to size, and to hand to the workers.
  explicit DpdkFastPath(DpdkSessionTables& tables);
  ~DpdkFastPath();

  DpdkFastPath(const DpdkFastPath&) = delete;
  DpdkFastPath& operator=(const DpdkFastPath&) = delete;

  /**
   * @brief Configure the ports, size the tables and start the workers.
   *
   * EAL must already be initialised (DpdkEal::Init).
   *
   * @param max_sessions Capacity for the session tables.
   * @throws std::runtime_error if a device or an lcore cannot be set up.
   */
  void Setup(uint32_t max_sessions);

  /// Stop the workers and close the ports. Idempotent.
  void TearDown();

  /// Log the port counters and what each worker has seen.
  void LogStatistics() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

#endif  // DPDK_FAST_PATH_H_
