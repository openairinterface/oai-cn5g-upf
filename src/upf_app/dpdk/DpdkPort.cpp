/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DpdkPort.h"

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdexcept>

#include "DpdkEal.h"
#include "logger.hpp"

//------------------------------------------------------------------------------
const char* ToString(PortRole role) {
  switch (role) {
    case PortRole::N3:
      return "N3";
    case PortRole::N6:
      return "N6";
    case PortRole::Shared:
      return "N3+N6";
  }
  return "unknown";
}

/// Parse "aa:bb:cc:dd:ee:ff" into a DPDK ethernet address.
bool ParseMacAddress(const std::string& text, rte_ether_addr& out) {
  if (text.empty()) return false;
  unsigned int bytes[RTE_ETHER_ADDR_LEN] = {};
  if (sscanf(
          text.c_str(), "%x:%x:%x:%x:%x:%x", &bytes[0], &bytes[1], &bytes[2],
          &bytes[3], &bytes[4], &bytes[5]) != RTE_ETHER_ADDR_LEN) {
    return false;
  }
  for (int i = 0; i < RTE_ETHER_ADDR_LEN; ++i) {
    if (bytes[i] > 0xFF) return false;
    out.addr_bytes[i] = static_cast<uint8_t>(bytes[i]);
  }
  return true;
}

std::string MacToString(const rte_ether_addr& mac) {
  char text[RTE_ETHER_ADDR_FMT_SIZE] = {};
  rte_ether_format_addr(text, sizeof(text), &mac);
  return std::string(text);
}

//------------------------------------------------------------------------------
DpdkPort::DpdkPort(PortRole role, const oai::config::dpdk_port_cfg_t& config)
    : role_(role),
      pci_address_(config.pci_address),
      rx_queues_(config.rx_queues),
      lcores_(DpdkEal::ParseCoreList(config.lcores)) {
  if (lcores_.empty()) {
    throw std::runtime_error(
        std::string("DPDK: no polling lcores configured for the ") +
        ToString(role) + " port");
  }
  if (rx_queues_ < lcores_.size()) {
    throw std::runtime_error(
        std::string("DPDK: the ") + ToString(role) + " port has " +
        std::to_string(rx_queues_) + " RX queue(s) for " +
        std::to_string(lcores_.size()) +
        " polling lcore(s); each lcore needs its own queue");
  }
}

//------------------------------------------------------------------------------
void DpdkPort::CreateMempool(const oai::config::dpdk_cfg_t& global) {
  const int socket = rte_eth_dev_socket_id(port_id_);
  const std::string name =
      "upf_mbuf_" + std::to_string(port_id_);

  mempool_ = rte_pktmbuf_pool_create(
      name.c_str(), global.num_mbufs, global.mbuf_cache_size, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE, socket < 0 ? SOCKET_ID_ANY : socket);

  if (mempool_ == nullptr) {
    throw std::runtime_error(
        "DPDK: cannot create the mbuf pool for port " +
        std::to_string(port_id_) + ": " + rte_strerror(rte_errno));
  }

  Logger::upf_app().info(
      "DPDK: %s port mbuf pool '%s': %u mbufs, cache %u, NUMA socket %d",
      ToString(role_), name.c_str(), global.num_mbufs, global.mbuf_cache_size,
      socket);
}

//------------------------------------------------------------------------------
void DpdkPort::Start(
    const oai::config::dpdk_cfg_t& global, uint16_t total_tx_queues) {
  if (rte_eth_dev_get_port_by_name(pci_address_.c_str(), &port_id_) != 0) {
    throw std::runtime_error(
        "DPDK: no device '" + pci_address_ +
        "' for the " + ToString(role_) +
        " port; check that it is bound to vfio-pci");
  }

  rte_eth_dev_info device_info{};
  if (rte_eth_dev_info_get(port_id_, &device_info) != 0) {
    throw std::runtime_error(
        "DPDK: cannot read the device info of port " +
        std::to_string(port_id_));
  }

  tx_queues_ = total_tx_queues;
  if (rx_queues_ > device_info.max_rx_queues ||
      tx_queues_ > device_info.max_tx_queues) {
    throw std::runtime_error(
        "DPDK: the " + std::string(ToString(role_)) + " port supports " +
        std::to_string(device_info.max_rx_queues) + " RX / " +
        std::to_string(device_info.max_tx_queues) +
        " TX queues, but the configuration asks for " +
        std::to_string(rx_queues_) + " / " + std::to_string(tx_queues_));
  }

  CreateMempool(global);

  // Ask for the offloads we want, but only those the device advertises: the
  // pipeline falls back to computing checksums itself.
  rte_eth_conf port_conf{};

  // Encapsulation adds an IPv4 + UDP + GTP-U + PDU Session Container header
  // (44 bytes) to a full-size DN packet, so both ports must carry more than a
  // standard frame or downlink traffic is dropped by the NIC.
  constexpr uint16_t kTunnelOverhead = 44;
  const uint16_t desired_mtu         = RTE_ETHER_MTU + kTunnelOverhead;
  port_conf.rxmode.mtu =
      device_info.max_mtu != 0 ? RTE_MIN(desired_mtu, device_info.max_mtu)
                               : desired_mtu;
  if (port_conf.rxmode.mtu < desired_mtu) {
    Logger::upf_app().warn(
        "DPDK: the %s port tops out at an MTU of %u, below the %u needed for "
        "full-size encapsulated packets; the data network MTU must be lowered "
        "accordingly",
        ToString(role_), port_conf.rxmode.mtu, desired_mtu);
  }
  if (port_conf.rxmode.mtu > RTE_ETHER_MTU) {
    // Frames now exceed the standard 1500-byte payload.
    port_conf.rxmode.offloads |= device_info.rx_offload_capa &
                                 RTE_ETH_RX_OFFLOAD_SCATTER;
  }
  port_conf.rxmode.offloads |=
      device_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM;
  port_conf.txmode.offloads =
      device_info.tx_offload_capa &
      (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM);

  // Spread traffic over the queues when more than one lcore polls the port.
  if (rx_queues_ > 1) {
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_hf =
        RTE_ETH_RSS_IP & device_info.flow_type_rss_offloads;
    if (port_conf.rx_adv_conf.rss_conf.rss_hf == 0) {
      Logger::upf_app().warn(
          "DPDK: port %u does not support IP RSS; queues may be unbalanced",
          port_id_);
      port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    }
  }

  if (rte_eth_dev_configure(port_id_, rx_queues_, tx_queues_, &port_conf) < 0) {
    throw std::runtime_error(
        "DPDK: cannot configure port " + std::to_string(port_id_) + ": " +
        rte_strerror(rte_errno));
  }

  uint16_t rx_descriptors = global.rx_descriptors;
  uint16_t tx_descriptors = global.tx_descriptors;
  if (rte_eth_dev_adjust_nb_rx_tx_desc(
          port_id_, &rx_descriptors, &tx_descriptors) < 0) {
    throw std::runtime_error(
        "DPDK: the descriptor counts are not acceptable for port " +
        std::to_string(port_id_));
  }

  const int socket = rte_eth_dev_socket_id(port_id_);
  const int socket_id = socket < 0 ? SOCKET_ID_ANY : socket;

  for (uint16_t queue = 0; queue < rx_queues_; ++queue) {
    rte_eth_rxconf rx_conf = device_info.default_rxconf;
    rx_conf.offloads       = port_conf.rxmode.offloads;
    if (rte_eth_rx_queue_setup(
            port_id_, queue, rx_descriptors, socket_id, &rx_conf, mempool_) <
        0) {
      throw std::runtime_error(
          "DPDK: cannot set up RX queue " + std::to_string(queue) +
          " of port " + std::to_string(port_id_));
    }
  }

  for (uint16_t queue = 0; queue < tx_queues_; ++queue) {
    rte_eth_txconf tx_conf = device_info.default_txconf;
    tx_conf.offloads       = port_conf.txmode.offloads;
    if (rte_eth_tx_queue_setup(
            port_id_, queue, tx_descriptors, socket_id, &tx_conf) < 0) {
      throw std::runtime_error(
          "DPDK: cannot set up TX queue " + std::to_string(queue) +
          " of port " + std::to_string(port_id_));
    }
  }

  if (rte_eth_dev_start(port_id_) < 0) {
    throw std::runtime_error(
        "DPDK: cannot start port " + std::to_string(port_id_) + ": " +
        rte_strerror(rte_errno));
  }
  started_ = true;

  if (global.promiscuous) {
    if (rte_eth_promiscuous_enable(port_id_) != 0) {
      Logger::upf_app().warn(
          "DPDK: cannot enable promiscuous mode on port %u", port_id_);
    }
  }

  if (rte_eth_macaddr_get(port_id_, &mac_) != 0) {
    throw std::runtime_error(
        "DPDK: cannot read the MAC address of port " +
        std::to_string(port_id_));
  }

  Logger::upf_app().info(
      "DPDK: %s port started — device %s, port id %u, MAC %s, %u RX / %u TX "
      "queues, link %s",
      ToString(role_), pci_address_.c_str(), port_id_,
      MacToString(mac_).c_str(), rx_queues_, tx_queues_,
      LinkIsUp() ? "up" : "down");
}

//------------------------------------------------------------------------------
bool DpdkPort::LinkIsUp() const {
  rte_eth_link link{};
  if (rte_eth_link_get_nowait(port_id_, &link) != 0) return false;
  return link.link_status == RTE_ETH_LINK_UP;
}

//------------------------------------------------------------------------------
void DpdkPort::LogStatistics() const {
  rte_eth_stats stats{};
  if (rte_eth_stats_get(port_id_, &stats) != 0) return;

  Logger::upf_app().info(
      "DPDK: %s port %u — rx %lu pkts / %lu bytes, tx %lu pkts / %lu bytes, "
      "rx errors %lu, tx errors %lu, missed %lu, no mbuf %lu",
      ToString(role_), port_id_, stats.ipackets, stats.ibytes, stats.opackets,
      stats.obytes, stats.ierrors, stats.oerrors, stats.imissed,
      stats.rx_nombuf);
}

//------------------------------------------------------------------------------
void DpdkPort::Stop() {
  if (!started_) return;

  rte_eth_dev_stop(port_id_);
  rte_eth_dev_close(port_id_);
  started_ = false;

  if (mempool_ != nullptr) {
    rte_mempool_free(mempool_);
    mempool_ = nullptr;
  }

  Logger::upf_app().info("DPDK: %s port %u stopped", ToString(role_), port_id_);
}
