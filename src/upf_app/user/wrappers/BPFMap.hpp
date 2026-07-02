/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file BPFMap.hpp
 * @brief C++ wrapper for BPF/eBPF maps
 *
 * This header-only wrapper class provides a type-safe, RAII-compliant
 * interface to BPF maps. It abstracts the low-level libbpf map operations
 * and provides:
 * - Type-safe map operations via templates
 * - Automatic error handling and logging
 * - CRUD operations: lookup, update, remove
 * - Map iteration support
 *
 * BPF Map Types Supported:
 * - HASH: Key-value hash table
 * - ARRAY: Zero-based indexed array
 * - LRU_HASH: Hash with LRU eviction
 * - PERCPU variants: Per-CPU versions of above
 *
 * Usage Example:
 * @code
 * BPFMap session_map(bpf_map_ptr, "session_map");
 *
 * // Lookup
 * uint32_t session_id;
 * if (session_map.Lookup(ue_ip, &session_id) == 0) {
 *   // Found session
 * }
 *
 * // Update
 * session_map.Update(ue_ip, session_id, BPF_ANY);
 *
 * // Remove
 * session_map.Remove(ue_ip);
 *
 * // Iterate
 * uint32_t key, next_key;
 * while (session_map.GetNextKey(key, next_key) == 0) {
 *   // Process key
 *   key = next_key;
 * }
 * @endcode
 *
 * Thread Safety: Operations are atomic at the BPF map level, but multiple
 * operations are not atomic as a group. Use external synchronization if needed.
 *
 * @note This implementation follows Google C++ Style Guide
 * @note Header-only for template functions
 */

#ifndef BPFMAP_HPP_
#define BPFMAP_HPP_

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <string>
#include "logger.hpp"
#include "BPFMapFormatters.hpp"
//#include "BPFMapFormattersOverloads.hpp"

/**
 * @class BPFMap
 * @brief Type-safe wrapper for BPF maps with CRUD operations
 *
 * Provides a C++ interface to BPF maps created by libbpf skeleton code.
 * Supports all standard BPF map operations with automatic error handling
 * and logging.
 *
 * Key Features:
 * - Template-based type safety for keys and values
 * - Automatic error logging with errno details
 * - RAII-style resource management
 * - Support for all BPF_* flags (BPF_ANY, BPF_NOEXIST, BPF_EXIST)
 *
 * Map Update Flags:
 * - BPF_ANY: Create new element or update existing
 * - BPF_NOEXIST: Create new element only (fail if exists)
 * - BPF_EXIST: Update existing element only (fail if not exists)
 *
 * @note Does not own the underlying bpf_map structure
 * @note This implementation follows Google C++ Style Guide
 */
class BPFMap {
 public:
  /**
   * @brief Constructor - wraps an existing BPF map
   *
   * @param bpf_map Pointer to libbpf map structure (from skeleton)
   * @param name Human-readable name for logging
   *
   * @note Does not take ownership of bpf_map pointer
   * @note bpf_map must remain valid for lifetime of this object
   */
  BPFMap(struct bpf_map* bpf_map, std::string name);

  /**
   * @brief Destructor - does not destroy underlying map
   *
   * The underlying BPF map is owned by the skeleton and is destroyed
   * when the skeleton is destroyed.
   */
  virtual ~BPFMap();

  /**
   * @brief Look up value by key in the map
   *
   * Wrapper for bpf_map_lookup_elem(). Retrieves the value associated
   * with the given key.
   *
   * @tparam KeyType Type of the key (must match BPF map key type)
   * @param key The key to look up
   * @param value Pointer to output buffer for value
   * @return 0 on success, negative errno on failure
   *
   * Return Values:
   * - 0: Success, value found and copied to output buffer
   * - -ENOENT: Key not found in map
   * - -EINVAL: Invalid parameters
   *
   * @note value buffer must be large enough for the value type
   *
   * Usage:
   * @code
   * uint32_t session_id;
   * int ret = map.Lookup(ue_ip, &session_id);
   * if (ret == 0) {
   *   Logger::upf_app().info("Found session: %u", session_id);
   * } else if (ret == -ENOENT) {
   *   Logger::upf_app().debug("Session not found");
   * }
   * @endcode
   */
  template<class KeyType>
  int Lookup(KeyType& key, void* value);

  /**
   * @brief Get the next key in the map (for iteration)
   *
   * Wrapper for bpf_map_get_next_key(). Used to iterate over all keys
   * in the map. To get the first key, pass a null/zero key.
   *
   * @tparam KeyType Type of the key
   * @param key Current key (or 0 for first key)
   * @param next_key Output parameter for next key
   * @return 0 on success, -1 on end of map, negative errno on error
   *
   * Return Values:
   * - 0: Success, next_key contains the next key
   * - -1: End of map reached (no more keys)
   * - Negative: Error occurred
   *
   * Iteration Pattern:
   * @code
   * uint32_t key = 0, next_key;
   *
   * // Get first key
   * if (map.GetNextKey(key, next_key) == 0) {
   *   key = next_key;
   *
   *   // Iterate remaining keys
   *   while (map.GetNextKey(key, next_key) == 0) {
   *     // Process key
   *     map.Lookup(key, &value);
   *     key = next_key;
   *   }
   * }
   * @endcode
   */
  template<class KeyType>
  int GetNextKey(KeyType& key, KeyType& next_key);

  /**
   * @brief Update or create a map entry
   *
   * Wrapper for bpf_map_update_elem(). Updates an existing entry or
   * creates a new one based on the flags parameter.
   *
   * @tparam KeyType Type of the key
   * @tparam ValueType Type of the value
   * @param key The key to update
   * @param value The value to store
   * @param flags Update behavior flags
   * @return 0 on success, negative errno on failure
   *
   * Flags:
   * - BPF_ANY: Create or update (default behavior)
   * - BPF_NOEXIST: Create only (fail if key exists)
   * - BPF_EXIST: Update only (fail if key doesn't exist)
   *
   * Return Values:
   * - 0: Success
   * - -EEXIST: Key exists (when using BPF_NOEXIST)
   * - -ENOENT: Key not found (when using BPF_EXIST)
   * - -E2BIG: Map is full
   *
   * @throws std::runtime_error on failure (with errno details)
   *
   * Usage:
   * @code
   * // Create or update
   * map.Update(ue_ip, session_id, BPF_ANY);
   *
   * // Create only (fail if exists)
   * try {
   *   map.Update(ue_ip, session_id, BPF_NOEXIST);
   * } catch (const std::runtime_error& e) {
   *   Logger::upf_app().warn("Session already exists");
   * }
   *
   * // Update only (fail if not exists)
   * map.Update(ue_ip, new_session_id, BPF_EXIST);
   * @endcode
   */
  template<class KeyType, class ValueType>
  int Update(KeyType& key, ValueType& value, int flags);

  /**
   * @brief Remove an entry from the map
   *
   * Wrapper for bpf_map_delete_elem(). Deletes the entry with the
   * specified key.
   *
   * @tparam KeyType Type of the key
   * @param key The key to remove
   * @return 0 on success, negative errno on failure
   *
   * Return Values:
   * - 0: Success, entry removed
   * - -ENOENT: Key not found (not an error for idempotent deletes)
   *
   * @throws std::runtime_error on failure
   *
   * Usage:
   * @code
   * try {
   *   map.Remove(ue_ip);
   *   Logger::upf_app().info("Session removed");
   * } catch (const std::runtime_error& e) {
   *   Logger::upf_app().warn("Session not found");
   * }
   * @endcode
   */
  template<class KeyType>
  int Remove(KeyType& key);

  /**
   * @brief Get the name of the BPF map
   *
   * Returns the human-readable name assigned during construction.
   * Useful for logging and debugging.
   *
   * @return std::string The map name
   */
  std::string GetName() const;

 private:
  struct bpf_map* bpf_map_;  ///< Pointer to libbpf map structure
  std::string name_;         ///< Human-readable map name for logging
};

//------------------------------------------------------------------------------
// Template Implementation
//------------------------------------------------------------------------------

template<class KeyType>
int BPFMap::Lookup(KeyType& key, void* value) {
  int map_fd = bpf_map__fd(bpf_map_);
  return bpf_map_lookup_elem(map_fd, &key, value);
}

//------------------------------------------------------------------------------
template<class KeyType, class ValueType>
int BPFMap::Update(KeyType& key, ValueType& value, int flags) {
  int map_fd = bpf_map__fd(bpf_map_);

  int ret = bpf_map_update_elem(map_fd, &key, &value, flags);

  if (ret != 0) {
    Logger::upf_app().error(
        "Failed to update map '%s': errno=%d (%s)", name_.c_str(), errno,
        strerror(errno));
    throw std::runtime_error("BPF map update failed");
  }

  // Fancy human-readable logging
  std::string key_str = upf::utils::FormatBPFValue(key);
  std::string val_str = upf::utils::FormatBPFValue(value);

  // const char* op = (flags == BPF_NOEXIST) ? "Add" :
  //                  (flags == BPF_EXIST)   ? "Update" :
  //                                           "Set";
  // Logger::upf_app().debug(
  //     "%s map '%s': [%s] → %s", op, name_.c_str(), key_str.c_str(),
  //     val_str.c_str());
  return ret;
}

//------------------------------------------------------------------------------
template<class KeyType>
int BPFMap::Remove(KeyType& key) {
  int map_fd = bpf_map__fd(bpf_map_);

  int ret = bpf_map_delete_elem(map_fd, &key);

  if (ret != 0) {
    Logger::upf_app().error(
        "Failed to remove key from map '%s': errno=%d (%s)", name_.c_str(),
        errno, strerror(errno));
    throw std::runtime_error("BPF map delete failed");
  }

  // Fancy human-readable logging
  std::string key_str = upf::utils::FormatBPFValue(key);

  Logger::upf_app().debug(
      "Remove value from Map '%s': [%s] -> *", name_.c_str(), key_str.c_str());
  return ret;
}

//------------------------------------------------------------------------------
template<class KeyType>
int BPFMap::GetNextKey(KeyType& key, KeyType& next_key) {
  int map_fd = bpf_map__fd(bpf_map_);
  int ret    = bpf_map_get_next_key(map_fd, &key, &next_key);

  // bpf_map_get_next_key() reports "no more keys" with ENOENT. Depending on the
  // libbpf version this surfaces as ret == -1 (errno=ENOENT) or ret == -ENOENT.
  // That is the normal loop-termination case for map iteration, not an error.
  if (ret != 0 && ret != -1 && ret != -ENOENT && errno != ENOENT) {
    Logger::upf_app().warn(
        "GetNextKey failed for map '%s': errno=%d", name_.c_str(), errno);
  }

  return ret;
}

#endif  // BPFMAP_HPP_
