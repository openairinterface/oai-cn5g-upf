// bpf_utils.hpp
/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#pragma once

#include <bpf/libbpf.h>
#include <string>
#include <cstdint>

namespace oai::utils::bpf {

/**
 * @brief Safely set the maximum entries of a BPF map.
 *
 * @param map       Pointer to the libbpf map handle.
 * @param map_name  Human-readable name for logging.
 * @param max_entries Desired maximum number of entries.
 * @return true on success, false otherwise.
 */
bool configure_map_max_entries(
    struct bpf_map* map, const std::string& map_name, uint32_t max_entries);

}  // namespace oai::utils::bpf
