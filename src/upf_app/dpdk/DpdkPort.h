/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DPDK_PORT_H_
#define DPDK_PORT_H_

#include <rte_ether.h>
#include <rte_mempool.h>

#include <string>
#include <vector>

#include "upf_config.hpp"

/**
 * @enum PortRole
 * @brief What a port carries.
 *
 * With one device for both interfaces the role is Shared, and the pipeline
 * decides uplink vs downlink by classifying the packet instead of by port.
 */
enum class PortRole : uint8_t {
  N3 = 0,  ///< GTP-U towards the RAN
  N6,      ///< Towards the data network
  Shared   ///< One device carrying both
};

const char* ToString(PortRole role);

/// Parse "aa:bb:cc:dd:ee:ff"; false when the text is not a MAC address.
bool ParseMacAddress(const std::string& text, rte_ether_addr& out);

/// Render a MAC address for logging.
std::string MacToString(const rte_ether_addr& mac);

/**
 * @class DpdkPort
 * @brief One configured and started ethernet device.
 *
 * Owns the mbuf pool it receives into, and knows the next hop to send to.
 */
class DpdkPort {
 public:
  DpdkPort(PortRole role, const oai::config::dpdk_port_cfg_t& config);

  DpdkPort(const DpdkPort&) = delete;
  DpdkPort& operator=(const DpdkPort&) = delete;

  /**
   * @brief Find the device, configure queues and start it.
   * @param global      EAL-wide settings (descriptors, mbuf pool sizing).
   * @param total_tx_queues TX queues to create: every polling lcore in the
   *        deployment owns one on every port, so it can transmit without
   *        locking.
   * @throws std::runtime_error if the device is missing or setup fails.
   */
  void Start(const oai::config::dpdk_cfg_t& global, uint16_t total_tx_queues);

  /// Stop and close the device. Idempotent.
  void Stop();

  [[nodiscard]] uint16_t id() const { return port_id_; }
  [[nodiscard]] PortRole role() const { return role_; }
  [[nodiscard]] uint16_t rx_queue_count() const { return rx_queues_; }
  [[nodiscard]] const std::vector<unsigned>& lcores() const { return lcores_; }
  [[nodiscard]] const rte_ether_addr& mac() const { return mac_; }
  [[nodiscard]] rte_mempool* mempool() const { return mempool_; }
  [[nodiscard]] bool started() const { return started_; }

  /// True when the device reports link up.
  [[nodiscard]] bool LinkIsUp() const;

  /// Log the device counters (packets, bytes, errors, missed).
  void LogStatistics() const;

 private:
  void CreateMempool(const oai::config::dpdk_cfg_t& global);

  PortRole role_;
  std::string pci_address_;
  uint16_t rx_queues_;
  uint16_t tx_queues_ = 0;
  std::vector<unsigned> lcores_;

  uint16_t port_id_     = 0;
  rte_mempool* mempool_ = nullptr;
  rte_ether_addr mac_{};
  bool started_ = false;
};

/**
 * @struct DpdkEgress
 * @brief Where one direction sends: a port and the next hop on it.
 *
 * Kept apart from DpdkPort because a single shared device serves both
 * directions with two different next hops (the gNB on N3, the data network
 * gateway on N6).
 */
struct DpdkEgress {
  const DpdkPort* port = nullptr;
  rte_ether_addr next_hop{};
  bool has_next_hop = false;

  [[nodiscard]] uint16_t port_id() const { return port->id(); }
  [[nodiscard]] const rte_ether_addr& source_mac() const {
    return port->mac();
  }
};

#endif  // DPDK_PORT_H_
