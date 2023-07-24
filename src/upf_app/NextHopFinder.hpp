#ifndef NEXT_HOP_FINDER_HPP
#define NEXT_HOP_FINDER_HPP

#include <string>
#include <memory>
#include <netinet/ether.h>

#include "logger.hpp"

class NextHopFinder {
 public:
  NextHopFinder();
  uint32_t retrieveNextHopIP(uint32_t destination_ip_);
  ether_addr* retrieveNextHopMAC(uint32_t next_hop_ip_);
  int calculateSubnetMask(uint32_t ip);
  int sameSubnet(uint32_t ip1, uint32_t ip2);

 private:
  std::string executeCommand(const std::string& command);
};

#endif  // NEXT_HOP_FINDER_HPP