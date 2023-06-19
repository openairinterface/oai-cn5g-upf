#ifndef __BPFMAP_H__
#define __BPFMAP_H__

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
// // #include <utils/LogDefines.h>
#include "logger.hpp"

/**
 * @brief This class abstracts the communication with a specific BPF map.
 */
class BPFMap {
 public:
  /**
   * @brief Construct a new BPFMap object.
   *
   * @param pBPFMap The bpf map compatible with libbpf.
   * @param name The name of the map.
   */
  BPFMap(struct bpf_map* pBPFMap, std::string name);
  /**
   * @brief Destroy the BPFMap object.
   */
  virtual ~BPFMap();
  /**
   * @brief Lookup a element in a specific position.
   * Wrappers the bpf_map_lookup function.
   *
   * @param key The key to be used to find the element.
   * @param pValue The element found.
   * @return 0 if it is success, cc. != 0.
   */
  template<class KeyType>
  int lookup(KeyType& key, void* pValue);
  /**
   * @brief Update a element in a specific position.
   * Wrappers the bpf_map_update function.
   *
   * @param key The key to be used to find the element.
   * @param value The new element.
   * @param flags
   * @return 0 if it is success, cc. != 0.
   */
  template<class KeyType, class ValueType>
  int update(KeyType& key, ValueType& value, int flags);
  /**
   * @brief Remove a element in a specific position.
   * Wrappers the bpf_map_delete function.
   *
   * @param key The key to be deleted.
   * @return 0 if it is success, cc. != 0.
   */
  template<class KeyType>
  int remove(KeyType& key);

  /**
   * @brief Get the Name of the BPF Map.
   *
   * @return std::string The name of the BPF map.
   */
  std::string getName() const;

 private:
  // TODO: Change to unique.
  // The bpf map.
  struct bpf_map* mpBPFMap;

  // The name of the BPF map.
  std::string mName;
};

template<class KeyType>
int BPFMap::lookup(KeyType& key, void* pValue) {
  // Do not put here.
  int mapFd        = bpf_map__fd(mpBPFMap);
  int lookupReturn = bpf_map_lookup_elem(mapFd, &key, pValue);

  if (lookupReturn != 0) {
    // LOG_INF("The key {} cannot be found in map {}", key, mName);
    Logger::upf_app().info(
        "The key %d cannot be found in map %s", key, mName.c_str());
  } else {
    // LOG_DBG("The key {} was found at {} map!", key, mName);
    Logger::upf_app().info(
        "The key %d was found at %s map!", key, mName.c_str());
  }
  return lookupReturn;
}

template<class KeyType, class ValueType>
int BPFMap::update(KeyType& key, ValueType& value, int flags) {
  // Do not put here.
  int mapFd        = bpf_map__fd(mpBPFMap);
  int updateReturn = bpf_map_update_elem(mapFd, &key, &value, flags);

  if (updateReturn != 0) {
    // FIXME: Maybe Key is not support by fmt.
    // LOG_ERROR("{}. The key {} cannot be updated in map {}",
    // strerror(updateReturn), key, mName);
    Logger::upf_app().error("The key cannot be updated in map ");
    throw std::runtime_error("The BPF map cannot be updated");
  } else {
    // LOG_DBG("The key {} was updated at {} map!", key, mName);
    // LOG_DBG("The key was updated at {} map!", mName);
    Logger::upf_app().debug("The key was updated at %s map! ", mName.c_str());
  }
  return updateReturn;
}

template<class KeyType>
int BPFMap::remove(KeyType& key) {
  // Do not put here.
  int mapFd        = bpf_map__fd(mpBPFMap);
  int deleteReturn = bpf_map_delete_elem(mapFd, &key);

  if (deleteReturn != 0) {
    // LOG_ERROR("{}. The key {} cannot be removed in map {}",
    // strerror(deleteReturn), key, mName);
    Logger::upf_app().error("The key cannot be removed in map ");
    throw std::runtime_error("The BPF map cannot be removed");
  } else {
    // LOG_DBG("The key {} was removed at {} map!", key, mName);
    // Logger::upf_app().error("The key %d was removed at %s map! ",key,
    // mName.c_str());
    Logger::upf_app().error("The key was updated at %s map! ", mName.c_str());
  }

  return deleteReturn;
}

#endif  // __BPFMAP_H__
