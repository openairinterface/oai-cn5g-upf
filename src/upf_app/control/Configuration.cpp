/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file Configuration.cpp
 * @brief Configuration Management Implementation
 * @author OpenAirInterface
 * @date 2025
 */

#include "Configuration.h"
#include <string>
#include "logger.hpp"
#include "upf_config.hpp"

using namespace oai::config;

extern upf_config upf_cfg;

// Static member initialization
std::string Configuration::gtp_interface_              = upf_cfg.n3.if_name;
std::string Configuration::udp_interface_              = upf_cfg.n6.if_name;
unsigned char Configuration::is_socket_buffer_enabled_ = 0;

//------------------------------------------------------------------------------
Configuration::Configuration(int argc, char** argv) {
  if (argc >= 2) {
    Configuration::gtp_interface_ = argv[1];
    Configuration::udp_interface_ = argv[2];
  }

  Logger::upf_app().debug(
      "GTP Interface: %s", Configuration::gtp_interface_.c_str());
  Logger::upf_app().debug(
      "UDP Interface: %s", Configuration::udp_interface_.c_str());

  for (int i = 1; i < argc; ++i) {
    Logger::upf_app().debug("arg %d = %s", i, argv[i]);
  }
}
