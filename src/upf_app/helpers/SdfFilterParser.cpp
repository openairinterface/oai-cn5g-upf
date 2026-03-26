/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "SdfFilterParser.hpp"
#include <regex>
#include <string>
#include <iostream>
#include <optional>
#include <cstdlib>
#include <vector>
#include <arpa/inet.h>
#include <unordered_map>
#include "sdf_filter.h"

//---------------------------------------------------------------------------------------------------------------
std::optional<uint16_t> SdfFilterParser::ParseProtocol(
    const std::string& protocol) {
  static const std::unordered_map<std::string, uint8_t> allowedProtocolMap = {
      // Standard IANA-assigned IP protocol numbers
      {"icmp", 1},    // IPv4 ICMP
      {"ip", 0},      // IP in IP
      {"tcp", 6},     // TCP over IP
      {"udp", 17},    // UDP over IP
      {"icmp6", 58},  // IPv6 ICMP ?
      /*
       * We can also accept numbers to specify protocol:
       *         eg: permit out 6 from any to any
       * So here:    permit out tcp from any to any
       */
      {"0", 0},    // icmp
      {"1", 1},    // ip
      {"6", 6},    // tcp
      {"17", 17},  // udp
      {"58", 58}   // icmp6 ?
  };

  auto it = allowedProtocolMap.find(protocol);
  if (it != allowedProtocolMap.end()) {
    return it->second;
  }
  return std::nullopt;
}

//---------------------------------------------------------------------------------------------------------------
std::optional<struct ip_subnet> SdfFilterParser::ParseCidrIp(
    const std::string& ipStr, const std::string& maskStr) {
  struct ip_subnet result;
  struct in6_addr addr;
  uint8_t ipType = 0;

  // Check if it's IPv4
  if (inet_pton(AF_INET, ipStr.c_str(), &addr) == 1) {
    ipType = 1;
    uint32_t ipv4_addr;
    std::memcpy(&ipv4_addr, &addr, sizeof(ipv4_addr));  // Copy IPv4 address
    result.ip = static_cast<u128>(htonl(ipv4_addr));    // Convert to big-endian
  }
  // Check if it's IPv6
  else if (inet_pton(AF_INET6, ipStr.c_str(), &addr) == 1) {
    ipType = 2;
    std::memcpy(&result.ip, &addr, sizeof(result.ip));  // Store IPv6 address
  } else {
    return std::nullopt;  // Invalid IP address
  }

  // Determine default mask length
  int maskLen = (ipType == 1) ? 32 : 128;

  // Parse mask if provided
  if (!maskStr.empty()) {
    try {
      int maskInt = std::stoi(maskStr);
      if (maskInt < 0 || maskInt > maskLen) {
        return std::nullopt;
      }
      maskLen = maskInt;
    } catch (...) {
      return std::nullopt;
    }
  }

  // Construct the subnet mask
  result.mask = (maskLen == 0) ? 0 : (~(static_cast<u128>(-1) >> maskLen));

  result.type = ipType;
  return result;
}

//---------------------------------------------------------------------------------------------------------------
std::optional<struct port_range> SdfFilterParser::ParsePortRange(
    const std::string& str) {
  std::regex re(R"(^(\d+)(?:-(\d+))?$)");
  std::smatch match;

  if (!std::regex_match(str, match, re)) {
    return std::nullopt;
  }

  struct port_range portRange;
  auto lower = ParsePort(match[1]);
  if (!lower) return std::nullopt;
  portRange.lower_bound = *lower;

  if (match[2].matched) {
    auto upper = ParsePort(match[2]);
    if (!upper) return std::nullopt;
    portRange.upper_bound = *upper;
  } else {
    portRange.upper_bound = portRange.lower_bound;
  }

  if (portRange.lower_bound > portRange.upper_bound) {
    return std::nullopt;
  }

  return portRange;
}

//---------------------------------------------------------------------------------------------------------------
std::optional<uint16_t> SdfFilterParser::ParsePort(const std::string& str) {
  try {
    size_t pos;
    unsigned long port64 = std::stoul(str, &pos, 10);
    if (pos != str.length() || port64 > 65535) {
      Logger::upf_app().error(
          "Invalid port. Port must be inside bounds [0, 65535].");
      return std::nullopt;
    }
    return static_cast<uint16_t>(port64);
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

//---------------------------------------------------------------------------------------------------------------

std::optional<struct sdf_filtr> SdfFilterParser::ParseSdfFilter(
    const std::string& flowDescription) {
  const std::string flowRegexStr =
      R"(^permit out (icmp|ip|tcp|udp|\d+) from (any|[\d.]+|[\da-fA-F:]+)(?:/(\d+))?(?:\s+(\d+|\d+-\d+))? to (assigned|any|[\d.]+|[\da-fA-F:]+)(?:/(\d+))?(?:\s+(\d+|\d+-\d+))?$)";
  std::regex re(flowRegexStr);
  // permit out (icmp|ip|tcp|udp|\d+) from
  // (any|[\d.]+|[\da-fA-F:]+)(?:/(\d+))?(?: (\d+|\d+-\d+))? to
  // (assigned|any|[\d.]+|[\da-fA-F:]+)(?:/(\d+))?(?: (\d+|\d+-\d+))?$
  //                        proto                        src src ports dst dst
  //                        port
  std::smatch match;

  if (!std::regex_match(flowDescription, match, re)) {
    Logger::upf_app().error(
        "SDF Filter: bad formatting. flow description  {{ %s }} must follow "
        "regex: {{ %s }}",
        flowDescription, flowRegexStr);
    // throw std::runtime_error("SDF Filter: bad formatting");
    return std::nullopt;
  }

  struct sdf_filtr sdf;
  auto protocol = ParseProtocol(match[1]);
  if (!protocol) return std::nullopt;
  sdf.protocol = *protocol;

  if (match[2] == "any") {
    if (match[3].matched) return std::nullopt;
    sdf.src_addr.type = 0;
    sdf.src_addr.ip   = 0;
    sdf.src_addr.mask = 0;
  } else {
    auto srcAddress = ParseCidrIp(match[2], match[3]);
    if (!srcAddress) return std::nullopt;
    sdf.src_addr = *srcAddress;
  }

  sdf.src_port = {0, 65535};
  if (match[4].matched) {
    auto srcPortRange = ParsePortRange(match[4]);
    if (!srcPortRange) return std::nullopt;
    sdf.src_port = *srcPortRange;
  }

  if (match[5] == "assigned" || match[5] == "any") {
    sdf.dst_addr = {0};
  } else {
    auto dstAddress = ParseCidrIp(match[5], match[6]);
    if (!dstAddress) return std::nullopt;
    sdf.dst_addr = *dstAddress;
  }

  sdf.dst_port = {0, 65535};
  if (match[7].matched) {
    auto dstPortRange = ParsePortRange(match[7]);
    if (!dstPortRange) return std::nullopt;
    sdf.dst_port = *dstPortRange;
  }

  sdf.session.seid = 0;
  sdf.session.qfi  = 0;
  return sdf;
}
