// bpf_utils.cpp
/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "bpf_utils.hpp"
#include "logger.hpp"

namespace oai::utils::bpf {

bool configure_map_max_entries(
    struct bpf_map* map, const std::string& map_name, uint32_t max_entries) {
  if (!map) {
    Logger::upf_app().error(
        "Cannot configure BPF map %s: null pointer", map_name);
    return false;
  }

  if (max_entries == 0) {
    Logger::upf_app().warn(
        "Map %s has zero max_entries — skipping configuration", map_name);
    return false;
  }

  int ret = bpf_map__set_max_entries(map, max_entries);
  if (ret < 0) {
    Logger::upf_app().error(
        "Failed to set max_entries=%d for map %s: %d", max_entries, map_name,
        strerror(-ret));
    return false;
  }

  Logger::upf_app().debug(
      "Configured map %s with max_entries=%d", map_name, max_entries);
  return true;
}

}  // namespace oai::utils::bpf
