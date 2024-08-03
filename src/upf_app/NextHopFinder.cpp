#include "NextHopFinder.hpp"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdexcept>

#include "CmdRunner.hpp"

/*---------------------------------------------------------------------------------------------------------------*/
// NextHopFinder::NextHopFinder() {}

/*---------------------------------------------------------------------------------------------------------------*/
int NextHopFinder::calculateSubnetMask(uint32_t ip) {
  int mask      = 0;
  uint32_t temp = ip;

  while (temp & 0x80000000U) {
    mask++;
    temp <<= 1;
  }

  return mask;
}

/*---------------------------------------------------------------------------------------------------------------*/
int NextHopFinder::sameSubnet(uint32_t ip1, uint32_t ip2) {
  int subnet_mask = calculateSubnetMask(ip1);
  uint32_t mask   = 0xFFFFFFFFU << (32 - subnet_mask);

  return (ip1 & mask) == (ip2 & mask);
}

/*---------------------------------------------------------------------------------------------------------------*/

uint32_t NextHopFinder::retrieveNextHopIP(uint32_t ipDest) {
  std::string cmd     = {};
  struct in_addr addr = {.s_addr = ipDest};
  char* ipAddress     = inet_ntoa(addr);

  if (ipAddress) {
    cmd = fmt::format("ip route get {} | awk '{print $3}'", ipAddress);
  }

  uint32_t nextHopIp = htonl(inet_addr(CmdRunner::exec(cmd).c_str()));

  if (!nextHopIp) {
    Logger::upf_app().error("The Next Hop IPv4 WAS NOT Retrieved");
    throw std::runtime_error("The Next Hop IPv4 WAS NOT Retrieved");
  }

  return nextHopIp;
}

/*---------------------------------------------------------------------------------------------------------------*/

ether_addr* NextHopFinder::retrieveNextHopMAC(uint32_t nextHopIp) {
  std::string cmd        = {};
  struct in_addr addr    = {.s_addr = nextHopIp};
  char* ipAddress        = inet_ntoa(addr);
  std::string nextHopMac = {};

  if (ipAddress) {
    cmd = fmt::format(
        "sudo arping -c 1 {} | awk '/from/ {{print $4}}'", ipAddress);
  }

  nextHopMac = CmdRunner::exec(cmd);

  if (nextHopMac.empty()) {
    Logger::upf_app().error("The Next Hop MAC WAS NOT Retrieved");
    throw std::runtime_error("The Next Hop MAC WAS NOT Retrieved");
  }

  Logger::upf_app().debug(
      "Next Hop <SRC IP, MAC Address> = <%s, %s>", ipAddress, nextHopMac);

  return ether_aton(nextHopMac.c_str());
}
