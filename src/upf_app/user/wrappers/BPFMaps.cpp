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
 * @file BPFMaps.cpp
 * @brief Implementation of BPF maps container
 * @author OpenAirInterface
 * @date 2025
 */

#include "BPFMaps.h"
#include <bpf/libbpf.h>
#include <cassert>
#include <string>
#include "logger.hpp"

//------------------------------------------------------------------------------
BPFMaps::BPFMaps(bpf_object_skeleton* bpf_object_skeleton)
    : bpf_object_skeleton_(bpf_object_skeleton) {
  // Validate skeleton
  if (!bpf_object_skeleton_) {
    Logger::upf_app().error("Null skeleton passed to BPFMaps constructor");
    throw std::invalid_argument("Invalid BPF skeleton");
  }

  // Check if there are any maps
  if (bpf_object_skeleton_->map_cnt > 0) {
    // Logger::upf_app().info(
    //     "Initializing BPFMaps with %u maps", bpf_object_skeleton_->map_cnt);

    // Create a BPFMap wrapper for each map in the skeleton
    for (unsigned int i = 0; i < bpf_object_skeleton_->map_cnt; i++) {
      std::string name(bpf_object_skeleton_->maps[i].name);
      maps_.emplace_back(*bpf_object_skeleton_->maps[i].map, name);

      // Logger::upf_app().debug("Wrapped BPF map: %s", name.c_str());
    }
  } else {
    Logger::upf_app().warn("BPF skeleton has no maps");
  }
}

//------------------------------------------------------------------------------
BPFMaps::~BPFMaps() {
  // BPFMap wrappers will be destroyed automatically (RAII)
  // The underlying BPF maps are owned by the skeleton and will be
  // destroyed when the skeleton is destroyed
}

//------------------------------------------------------------------------------
BPFMap& BPFMaps::GetMap(const char* name) {
  // Validate input
  if (!name) {
    Logger::upf_app().error("Null map name passed to GetMap()");
    throw std::invalid_argument("Map name cannot be null");
  }

  // Check if we have any maps
  if (maps_.empty()) {
    Logger::upf_app().error("No maps available in skeleton");
    throw std::runtime_error("BPF skeleton has no maps");
  }

  // Search for the map by name
  std::string name_str(name);
  for (unsigned int i = 0; i < bpf_object_skeleton_->map_cnt; i++) {
    std::string map_name(bpf_object_skeleton_->maps[i].name);
    if (name_str == map_name) {
      return maps_[i];
    }
  }

  // Map not found
  Logger::upf_app().error("BPF map '%s' not found in skeleton", name);
  throw std::runtime_error("Map not found");
}
