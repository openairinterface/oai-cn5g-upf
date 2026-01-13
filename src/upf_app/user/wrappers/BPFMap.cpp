/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file BPFMap.cpp
 * @brief Implementation of BPF map wrapper
 */

#include "BPFMap.hpp"
#include <string>

//------------------------------------------------------------------------------
BPFMap::BPFMap(struct bpf_map* bpf_map, std::string name)
    : bpf_map_(bpf_map), name_(name) {}

//------------------------------------------------------------------------------
BPFMap::~BPFMap() {
  // Note: We do not destroy the underlying bpf_map here
  // The map is owned by the BPF skeleton and will be destroyed
  // when the skeleton is destroyed
}

//------------------------------------------------------------------------------
std::string BPFMap::GetName() const {
  return name_;
}
