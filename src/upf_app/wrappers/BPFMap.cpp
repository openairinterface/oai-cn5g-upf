#include "BPFMap.hpp"
#include <string>

// TODO: Pass bpf_map_skeleton.
BPFMap::BPFMap(struct bpf_map* pBPFMap, std::string name)
    : mpBPFMap(pBPFMap), mName(name) {}

//---------------------------------------------------------------------------------------------------------------
BPFMap::~BPFMap() {}

//---------------------------------------------------------------------------------------------------------------
std::string BPFMap::getName() const {
  return mName;
}

//---------------------------------------------------------------------------------------------------------------
int BPFMap::resize(uint32_t max_entries) {
  if (!mpBPFMap) return -EINVAL;

  if (bpf_map__fd(mpBPFMap) >= 0)  // Ensure map is not already loaded
    return -EBUSY;

  int ret = bpf_map__set_max_entries(mpBPFMap, max_entries);
  if (ret != 0) {
    Logger::upf_app().error("Failed to resize BPF map: %s", mName.c_str());
    return ret;
  }

  Logger::upf_app().info(
      "Resized BPF map: %s to %u entries", mName.c_str(), max_entries);
  return 0;
}