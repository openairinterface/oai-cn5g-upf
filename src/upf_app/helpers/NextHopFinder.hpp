#ifndef NEXT_HOP_FINDER_HPP
#define NEXT_HOP_FINDER_HPP

#include <string>
//#include <memory>
#include <netinet/ether.h>

#include "logger.hpp"

class NextHopFinder {
 public:
  /**
   * @brief Retrieve next hop IPv4 address.
   * @param srcIP Local IPv4 address, in network byte order.
   * @param dstIP Destination IPv4 address, in network byte order.
   * @returns Next hop IPv4 address, in network byte order.
   * @throw std::invalid_argument Invalid srcIP or dstIP.
   * @throw std::runtime_error Unable to retrieve next hop.
   *
   * If @p dstIP is in the same subnet as @p srcIP , returns @p dstIP .
   * Otherwise, returns the IPv4 gateway needed to reach @p dstIP .
   */
  static uint32_t retrieveNextHopIP(uint32_t srcIP, uint32_t dstIP);

  /**
   * @brief Retrieve MAC address of an IPv4 address in the same subnet.
   * @param dstIP Target IPv4 address, in network byte order.
   * @returns MAC-48 address.
   * @throw std::invalid_argument Invalid dstIP.
   * @throw std::runtime_error Unable to retrieve MAC address.
   */
  static ether_addr retrieveNextHopMAC(uint32_t dstIP);
};

#endif  // NEXT_HOP_FINDER_HPP