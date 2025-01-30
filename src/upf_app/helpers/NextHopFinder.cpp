#include "NextHopFinder.hpp"
#include <nlohmann/json.hpp>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdexcept>

#include "CmdRunner.hpp"

/*---------------------------------------------------------------------------------------------------------------*/
// NextHopFinder::NextHopFinder() {}

/*---------------------------------------------------------------------------------------------------------------*/

/**
 * @brief Extract next hop IP from iproute2 JSON result.
 */
static std::string extractNextHopIP(const nlohmann::json& data) {
  // same subnet example:
  // [{"dst":"10.30.6.1","from":"10.30.6.95","dev":"enp3s0","flags":[],"uid":1000,"cache":[]}]
  //
  // different subnet example:
  // [{"dst":"1.1.1.1","from":"172.17.0.2","gateway":"172.17.0.1","dev":"eth0","flags":[],"uid":0,"cache":[]}]

  if (!data.is_array()) {
    return "";
  }

  for (const auto& row : data) {
    if (!row.is_object()) {
      continue;
    }

    auto gateway = row.find("gateway");
    if (gateway != row.end() && gateway->is_string()) {
      return gateway->get<std::string>();
    }

    auto dst = row.find("dst");
    if (dst != row.end() && dst->is_string()) {
      return dst->get<std::string>();
    }
  }

  return "";
}

/*---------------------------------------------------------------------------------------------------------------*/

uint32_t NextHopFinder::retrieveNextHopIP(uint32_t srcIP, uint32_t dstIP) {
  in_addr srcAddr = {.s_addr = srcIP};
  in_addr dstAddr = {.s_addr = dstIP};
  char srcStr[INET_ADDRSTRLEN];
  char dstStr[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &srcAddr, srcStr, sizeof(srcStr)) == nullptr) {
    throw std::invalid_argument(
        "NextHopFinder::retrieveNextHopIP: invalid srcIP");
  }
  if (inet_ntop(AF_INET, &dstAddr, dstStr, sizeof(dstStr)) == nullptr) {
    throw std::invalid_argument(
        "NextHopFinder::retrieveNextHopIP: invalid dstIP");
  }

  std::string cmd = fmt::format("ip -j route get {} from {}", dstStr, srcStr);
  Logger::upf_app().debug(
      "Invoking iproute2 to retrieve nexthop from %s to %s: %s", srcStr, dstStr,
      cmd.data());
  std::string output = CmdRunner::exec(cmd);
  nlohmann::json data;
  try {
    data = nlohmann::json::parse(output);
  } catch (const nlohmann::json::parse_error&) {
    Logger::upf_app().error("iproute2 command returned bad JSON data");
    throw std::runtime_error(
        "NextHopFinder::retrieveNextHopIP: invalid iproute2 output");
  }

  std::string nhStr = extractNextHopIP(data);
  in_addr nhAddr{};
  if (nhStr.empty() || inet_pton(AF_INET, nhStr.data(), &nhAddr) != 1) {
    Logger::upf_app().error("The Next Hop IPv4 WAS NOT Retrieved");
    throw std::runtime_error(
        "NextHopFinder::retrieveNextHopIP: empty iproute2 output");
  }

  return nhAddr.s_addr;
}

/*---------------------------------------------------------------------------------------------------------------*/

ether_addr NextHopFinder::retrieveNextHopMAC(uint32_t dstIP) {
  in_addr dstAddr = {.s_addr = dstIP};
  char dstStr[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &dstAddr, dstStr, sizeof(dstStr)) == nullptr) {
    throw std::invalid_argument(
        "NextHopFinder::retrieveNextHopMAC: invalid dstIP");
  }

  std::string cmd =
      fmt::format("sudo arping -c 1 {} | awk '/from/ {{print $4}}'", dstStr);
  Logger::upf_app().debug(
      "Invoking arping to retrieve MAC of %s: %s", dstStr, cmd.data());
  std::string output = CmdRunner::exec(cmd);

  ether_addr mac;
  if (output.empty() || ether_aton_r(output.data(), &mac) == nullptr) {
    Logger::upf_app().error("The Next Hop MAC WAS NOT Retrieved");
    throw std::runtime_error(
        "NextHopFinder::retrieveNextHopMAC: invalid arping output");
  }

  Logger::upf_app().debug(
      "Next Hop <SRC IP, MAC Address> = <%s, %s>", dstStr, output.data());

  return mac;
}
