#include "NextHopFinder.hpp"
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <types.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <iostream>
#include <stdexcept>
#include <arpa/inet.h>

#define COMMAND_MAX_LENGTH 256
#define OUTPUT_MAX_LENGTH 256

/*****************************************************************************************************************/
NextHopFinder::NextHopFinder() {}

/*****************************************************************************************************************/
int NextHopFinder::calculateSubnetMask(uint32_t ip) {
  int mask      = 0;
  uint32_t temp = ip;

  while (temp & 0x80000000U) {
    mask++;
    temp <<= 1;
  }

  return mask;
}

/*****************************************************************************************************************/
int NextHopFinder::sameSubnet(uint32_t ip1, uint32_t ip2) {
  int subnet_mask = calculateSubnetMask(ip1);
  uint32_t mask   = 0xFFFFFFFFU << (32 - subnet_mask);

  return (ip1 & mask) == (ip2 & mask);
}

/*****************************************************************************************************************/
u_int32_t NextHopFinder::retrieveNextHopIP(uint32_t destination_ip) {
  char command[COMMAND_MAX_LENGTH];

  struct in_addr addr;
  addr.s_addr     = destination_ip;
  char* ipAddress = inet_ntoa(addr);

  if (ipAddress == nullptr) {
    Logger::upf_app().error("The Next Hop IPv4 WAS NOT Retrieved");
    throw std::runtime_error("The Next Hop IPv4 WAS NOT Retrieved");
  }

  sprintf(command, "ip route get %s | awk '{print $3}'", ipAddress);
  u_int32_t next_hop_ip = htonl(inet_addr(executeCommand(command).c_str()));

  if (!next_hop_ip) {
    Logger::upf_app().error("The Next Hop IPv4 WAS NOT Retrieved");
    throw std::runtime_error("The Next Hop IPv4 WAS NOT Retrieved");
  }

  return next_hop_ip;
}

/*****************************************************************************************************************/

ether_addr* NextHopFinder::retrieveNextHopMAC(uint32_t next_hop_ip) {
  char command[COMMAND_MAX_LENGTH];

  struct in_addr addr;
  addr.s_addr     = next_hop_ip;
  char* ipAddress = inet_ntoa(addr);

  if (ipAddress == nullptr) {
    Logger::upf_app().error("The Next Hop IPv4 WAS NOT Retrieved");
    throw std::runtime_error("The Next Hop IPv4 WAS NOT Retrieved");
  }

  sprintf(command, "sudo arping -c 1 %s | awk '/from/ {print $4}'", ipAddress);
  // Logger::upf_app().debug("Next Hop SRC IP = %s", ipAddress);
  Logger::upf_app().debug(
      "Next Hop <SRC IP, MAC Address> = <%s, %s>", ipAddress,
      executeCommand(command).c_str());

  ether_addr* next_hop_mac;
  __builtin_memset(&next_hop_mac, 0, sizeof(ether_addr));
  next_hop_mac = ether_aton(executeCommand(command).c_str());

  if (next_hop_mac == nullptr) {
    Logger::upf_app().error("The Next Hop MAC WAS NOT Retrieved");
    throw std::runtime_error("The Next Hop MAC WAS NOT Retrieved");
  }

  return next_hop_mac;
}

/*****************************************************************************************************************/
std::string NextHopFinder::executeCommand(const std::string& command) {
  char output[OUTPUT_MAX_LENGTH];
  FILE* fp = popen(command.c_str(), "r");

  if (fp == nullptr) {
    Logger::upf_app().error("Failed to Run the Command: %s\n", command.c_str());
    return "";
  }

  fgets(output, OUTPUT_MAX_LENGTH, fp);
  pclose(fp);
  return output;
}

/*****************************************************************************************************************/
