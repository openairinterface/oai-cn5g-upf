/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
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
std::string Configuration::gtp_interface_ = upf_cfg.n3.if_name;
std::string Configuration::udp_interface_ = upf_cfg.n6.if_name;
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
