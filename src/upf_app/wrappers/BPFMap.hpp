#ifndef __BPFMAP_H__
#define __BPFMAP_H__

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "logger.hpp"

/**************************************************************************************************/
/**
 * @brief This class abstracts the communication with a specific BPF map.
 */
class BPFMap {
 public:
  /**************************************************************************************************/
  /**
   * @brief Construct a new BPFMap object.
   *
   * @param pBPFMap The bpf map compatible with libbpf.
   * @param name The name of the map.
   */
  BPFMap(struct bpf_map* pBPFMap, std::string name);

  /**************************************************************************************************/
  /**
   * @brief Destroy the BPFMap object.
   */
  virtual ~BPFMap();

  /**************************************************************************************************/
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

  /**************************************************************************************************/
  /**
   * @brief Get the nex element in the map.
   * Wrappers the bpf_get_next_key function.
   *
   * @param key The key to be used to find the element.
   * @param next_key a pointer to the next element in the map.
   * @return 0 if it is success, cc. != 0.
   */
  template<class KeyType>
  int get_next_elem(KeyType& key, KeyType& next_key);

  /**************************************************************************************************/
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

  /**************************************************************************************************/
  /**
   * @brief Remove a element in a specific position.
   * Wrappers the bpf_map_delete function.
   *
   * @param key The key to be deleted.
   * @return 0 if it is success, cc. != 0.
   */
  template<class KeyType>
  int remove(KeyType& key);

  /**************************************************************************************************/
  /**
   * @brief Get the Name of the BPF Map.
   *
   * @return std::string The name of the BPF map.
   */
  std::string getName() const;

  /**************************************************************************************************/
 private:
  // TODO: Change to unique.
  // The bpf map.
  struct bpf_map* mpBPFMap;

  // The name of the BPF map.
  std::string mName;
};

/**************************************************************************************************/
template<class KeyType>
int BPFMap::lookup(KeyType& key, void* pValue) {
  // Do not put here.
  int mapFd        = bpf_map__fd(mpBPFMap);
  int lookupReturn = bpf_map_lookup_elem(mapFd, &key, pValue);

  if (lookupReturn != 0) {
    Logger::upf_app().warn(
        "The key is not found in the map: %s", mName.c_str());
  } else {
    Logger::upf_app().debug("The key is found in the map: %s", mName.c_str());
  }
  return lookupReturn;
}

/**************************************************************************************************/
template<class KeyType, class ValueType>
int BPFMap::update(KeyType& key, ValueType& value, int flags) {
  int mapFd        = bpf_map__fd(mpBPFMap);
  int updateReturn = bpf_map_update_elem(mapFd, &key, &value, flags);

  if (updateReturn != 0) {
    // FIXME: Maybe Key is not support by fmt.
    Logger::upf_app().error("The key cannot be updated in map");
    throw std::runtime_error("The BPF map cannot be updated");
  } else {
    Logger::upf_app().debug("The key is updated in the map: %s", mName.c_str());
  }
  return updateReturn;
}

/**************************************************************************************************/
template<class KeyType>
int BPFMap::remove(KeyType& key) {
  // Do not put here.
  int mapFd        = bpf_map__fd(mpBPFMap);
  int deleteReturn = bpf_map_delete_elem(mapFd, &key);

  if (deleteReturn != 0) {
    Logger::upf_app().error("The key cannot be removed in map ");
    throw std::runtime_error("The BPF map cannot be removed");
  } else {
    Logger::upf_app().debug(
        "The key is removed from the map: %s", mName.c_str());
  }

  return deleteReturn;
}

/**************************************************************************************************/
template<class KeyType>
int BPFMap::get_next_elem(KeyType& key, KeyType& next_key) {
  int mapFd   = bpf_map__fd(mpBPFMap);
  int ret_val = bpf_map_get_next_key(mapFd, &key, &next_key);

  if ((ret_val != 0) && (ret_val != -1)) {
    Logger::upf_app().warn(
        "The key is not found in the map: %s\n", mName.c_str());
  }

  return ret_val;
}

/**************************************************************************************************/
#endif  // __BPFMAP_H__
