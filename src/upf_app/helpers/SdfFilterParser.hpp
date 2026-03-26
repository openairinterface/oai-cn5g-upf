/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#ifndef SDF_FILTER_PARSER_HPP
#define SDF_FILTER_PARSER_HPP

#include <string>
//#include <memory>
#include <netinet/ether.h>
#include <iostream>
#include <optional>
#include <cstdlib>

#include "logger.hpp"

class SdfFilterParser {
 public:
  // SdfFilterParser();
  static std::optional<uint16_t> ParseProtocol(const std::string& protocol);
  static std::optional<struct ip_subnet> ParseCidrIp(
      const std::string& ipStr, const std::string& maskStr);
  static std::optional<struct port_range> ParsePortRange(
      const std::string& str);
  static std::optional<struct sdf_filtr> ParseSdfFilter(
      const std::string& flowDescription);

 private:
  static std::optional<uint16_t> ParsePort(const std::string& str);
};

#endif  // SDF_FILTER_PARSER_HPP
