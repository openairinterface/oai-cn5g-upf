/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file bpf_utils.cpp
 * @brief Implementation of BPF utility functions
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
