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
 * @file BPFMaps.h
 * @brief Container for all BPF maps from a skeleton
 * @author OpenAirInterface
 * @date 2025
 *
 * This class provides centralized access to all BPF maps within a
 * libbpf skeleton. It creates BPFMap wrappers for each map and provides
 * lookup by name.
 *
 * Usage Pattern:
 * @code
 * // During BPF program initialization:
 * auto maps = std::make_shared<BPFMaps>(skeleton->skeleton);
 *
 * // Access maps by name:
 * BPFMap& session_map = maps->GetMap("session_map");
 * BPFMap& arp_table = maps->GetMap("arp_table_map");
 *
 * // Use the maps:
 * session_map.Update(ue_ip, session_id, BPF_ANY);
 * @endcode
 *
 * Design:
 * - Wraps the skeleton's bpf_object_skeleton structure
 * - Creates BPFMap wrappers for all maps at construction
 * - Provides map lookup by name
 * - RAII-compliant (cleans up wrappers automatically)
 *
 * @note This implementation follows Google C++ Style Guide
 */

#ifndef BPFMAPS_H_
#define BPFMAPS_H_

#include <vector>
#include <wrappers/BPFMap.hpp>

/**
 * @class BPFMaps
 * @brief Container and accessor for all BPF maps in a skeleton
 *
 * Provides centralized management of all BPF maps from a libbpf skeleton.
 * Automatically creates BPFMap wrappers for each map and provides name-based
 * lookup.
 *
 * Key Features:
 * - Automatic discovery of all maps in skeleton
 * - Name-based map lookup
 * - RAII resource management
 * - Exception-based error handling
 *
 * Thread Safety: Not thread-safe. Create and use from single thread.
 *
 * Lifecycle:
 * 1. Constructor: Wraps all maps from skeleton
 * 2. Usage: GetMap() for name-based access
 * 3. Destructor: Automatic cleanup of wrappers
 *
 * @note Does not own the skeleton - skeleton must outlive BPFMaps
 * @note This implementation follows Google C++ Style Guide
 */
class BPFMaps {
 public:
  /**
   * @brief Constructor - wraps all maps from skeleton
   *
   * Iterates through all maps in the skeleton and creates BPFMap
   * wrappers for each one. The wrappers are stored internally for
   * later retrieval by name.
   *
   * @param bpf_object_skeleton Pointer to libbpf skeleton structure
   *
   * @note skeleton must remain valid for lifetime of this object
   * @note Automatically discovers all maps in skeleton
   *
   * @throws May throw if skeleton is invalid
   */
  explicit BPFMaps(bpf_object_skeleton* bpf_object_skeleton);

  /**
   * @brief Destructor - cleans up map wrappers
   *
   * Destroys all BPFMap wrapper objects. The underlying BPF maps
   * remain in the kernel and are owned by the skeleton.
   */
  virtual ~BPFMaps();

  /**
   * @brief Get a BPF map by name
   *
   * Looks up a map by its name as defined in the BPF program source code.
   * The name must match exactly (case-sensitive).
   *
   * @param name The name of the map (e.g., "session_map", "arp_table_map")
   * @return BPFMap& Reference to the map wrapper
   *
   * @throws std::runtime_error if map not found
   *
   * Common Map Names in UPF:
   * - "session_by_ue_ip_map": UE IP to session mapping
   * - "arp_table_map": ARP resolution table
   * - "redirect_interfaces_map": Interface redirection map
   * - "pdrs_per_session_map": PDRs for each session
   * - "rules_match_pdr_map": Rule matching state
   * - "sdf_filters_map": SDF filter definitions
   *
   * Usage:
   * @code
   * try {
   *   BPFMap& map = maps->GetMap("session_map");
   *   map.Update(key, value, BPF_ANY);
   * } catch (const std::runtime_error& e) {
   *   Logger::upf_app().error("Map not found: %s", e.what());
   * }
   * @endcode
   */
  BPFMap& GetMap(const char* name);

  /**
   * @brief Get number of maps in the skeleton
   *
   * @return size_t Number of BPF maps
   */
  size_t GetMapCount() const { return maps_.size(); }

  // Delete copy constructor and assignment (non-copyable)
  BPFMaps(const BPFMaps&) = delete;
  BPFMaps& operator=(const BPFMaps&) = delete;

 private:
  /**
   * @brief Pointer to the skeleton structure
   *
   * Used to access map metadata and iterate through maps.
   * Does not own the skeleton.
   */
  bpf_object_skeleton* bpf_object_skeleton_;

  /**
   * @brief Vector of all BPFMap wrappers
   *
   * One wrapper for each map in the skeleton. Indexed to match
   * the skeleton's maps array.
   */
  std::vector<BPFMap> maps_;
};

#endif  // BPFMAPS_H_
