/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef BPF_UTILS_HPP_
#define BPF_UTILS_HPP_

#include <bpf/libbpf.h>
#include <cstdint>
#include <string>

namespace oai {
namespace utils {
namespace bpf {

/**
 * @brief Configure maximum entries for a BPF map
 *
 * Sets the max_entries parameter for a BPF map before it's loaded into
 * the kernel. This is required for dynamically-sized maps like HASH and
 * ARRAY maps.
 *
 * Important Notes:
 * - Must be called AFTER skeleton open, BEFORE skeleton load
 * - Cannot be changed after map is loaded
 * - Affects memory usage in kernel
 *
 * @param map Pointer to the libbpf map handle
 * @param map_name Human-readable name for logging (e.g., "session_map")
 * @param max_entries Desired maximum number of entries
 * @return true on success, false on failure
 *
 * Usage:
 * @code
 * struct my_bpf_skel* skel = my_bpf__open();
 * 
 * // Configure map sizes
 * ConfigureMapMaxEntries(skel->maps.session_map, "session_map", 10000);
 * ConfigureMapMaxEntries(skel->maps.arp_table, "arp_table", 1000);
 * 
 * // Now load the program
 * my_bpf__load(skel);
 * @endcode
 *
 * Error Conditions:
 * - Null map pointer
 * - Zero max_entries
 * - Map already loaded
 * - Kernel resource limits
 *
 * @see bpf_map__set_max_entries() for libbpf details
 */
bool ConfigureMapMaxEntries(
    struct bpf_map* map, const std::string& map_name, uint32_t max_entries);

}  // namespace bpf
}  // namespace utils
}  // namespace oai

#endif  // BPF_UTILS_HPP_
