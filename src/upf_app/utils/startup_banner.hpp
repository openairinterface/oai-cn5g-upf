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

#ifndef FILE_STARTUP_BANNER_HPP_SEEN
#define FILE_STARTUP_BANNER_HPP_SEEN

#include <string>

namespace oai::config {
class upf_config;
}

/**
 * @brief Display startup banner with version information
 */
void DisplayStartupBanner();

/**
 * @brief Display concise configuration summary
 * @param cfg UPF configuration
 */
void DisplayConfigSummary(const oai::config::upf_config& cfg);

/**
 * @brief Display network interface configuration
 * @param cfg UPF configuration
 */
void DisplayNetworkInterfaces(const oai::config::upf_config& cfg);

/**
 * @brief Display data plane status and BPF maps
 * @param cfg UPF configuration
 */
void DisplayDataPlaneStatus(const oai::config::upf_config& cfg);

/**
 * @brief Display XDP/TC configuration summary
 *
 * Shows XDP modes (Native/SKB) and BPF statistics
 */
void DisplayXdpConfiguration(
    const oai::config::upf_config& cfg, const std::string& n3_xdp_mode,
    const std::string& n6_xdp_mode, size_t total_maps);

/**
 * @brief Display ready message
 */
void DisplayReadyMessage();

#endif /* FILE_STARTUP_BANNER_HPP_SEEN */