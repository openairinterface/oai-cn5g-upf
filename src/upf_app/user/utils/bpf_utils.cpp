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
 * @file bpf_utils.cpp
 * @brief Implementation of BPF utility functions
 * @author OpenAirInterface
 * @date 2025
 */

#include "bpf_utils.hpp"
#include <cstring>
#include "logger.hpp"

namespace oai {
namespace utils {
namespace bpf {

//------------------------------------------------------------------------------
bool ConfigureMapMaxEntries(
    struct bpf_map* map, const std::string& map_name, uint32_t max_entries) {
  // Validate input
  if (!map) {
    Logger::upf_app().error(
        "Cannot configure BPF map '%s': null pointer", map_name.c_str());
    return false;
  }

  if (max_entries == 0) {
    Logger::upf_app().warn(
        "Map '%s' has zero max_entries - skipping configuration",
        map_name.c_str());
    return false;
  }

  // Set max entries using libbpf API
  int ret = bpf_map__set_max_entries(map, max_entries);
  if (ret < 0) {
    Logger::upf_app().error(
        "Failed to set max_entries=%u for map '%s': %s", max_entries,
        map_name.c_str(), strerror(-ret));
    return false;
  }

  // Removed verbose log - replaced by summary in upf_xdp_user.cpp
  // Logger::upf_app().debug(
  //     "Configured map '%s' with max_entries=%u", map_name.c_str(),
  //     max_entries);
  return true;
}

}  // namespace bpf
}  // namespace utils
}  // namespace oai
