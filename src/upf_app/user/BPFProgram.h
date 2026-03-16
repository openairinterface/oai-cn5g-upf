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

// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Boy Scout cleanup:
 *                - Removed duplicate @note "Follows Google C++ Style Guide"
 *                  from both @file and @class blocks — adds no information.
 *                - Added changelog block with clang-format guards.
 * 3GPP Refs:   n/a — no PFCP §-refs in this file.
 */
// clang-format on

/**
 * @file BPFProgram.h
 * @brief Base class for BPF/eBPF programs in UPF
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * This is the abstract base class for all BPF/eBPF programs used in the
 * User Plane Function. It provides common functionality like program ID
 * management and serves as the foundation for specialized BPF programs
 * (XDP programs, TC programs, etc.).
 *
 * Design Pattern: Template Method Pattern - derived classes implement
 * specific BPF program types while inheriting common functionality.
 *
 * @note This implementation follows Google C++ Style Guide
 */

#ifndef BPFPROGRAM_H_
#define BPFPROGRAM_H_

#include <cstdint>

/**
 * @class BPFProgram
 * @brief Abstract base class for BPF/eBPF programs
 *
 * Provides common functionality for all BPF programs in the UPF:
 * - Unique program ID assignment
 * - Basic lifecycle management interface
 * - Program identification
 *
 * Derived classes implement specific BPF program types:
 * - UPF_XDPProgram: XDP programs for fast packet processing
 * - QERProgram: TC-BPF programs for QoS enforcement
 *
 * Thread Safety: ID counter is NOT thread-safe. Create programs sequentially
 * during initialization.
 */
class BPFProgram {
 public:
  /**
   * @brief Constructor - assigns unique program ID
   *
   * Automatically increments the static ID counter to ensure each
   * BPF program instance has a unique identifier.
   */
  BPFProgram();

  /**
   * @brief Virtual destructor for proper cleanup of derived classes
   */
  virtual ~BPFProgram();

  /**
   * @brief Get the unique identifier of this BPF program
   *
   * @return uint32_t The program's unique ID
   *
   * Usage:
   * @code
   * std::shared_ptr<BPFProgram> program = ...;
   * uint32_t id = program->GetId();
   * Logger::upf_app().info("BPF Program ID: %u", id);
   * @endcode
   */
  uint32_t GetId() const;

 protected:
  uint32_t id_;  ///< Unique identifier for this BPF program instance

 private:
  /**
   * @brief Static counter for assigning unique IDs
   *
   * Incremented each time a BPFProgram is constructed. Starts at 1.
   *
   * @warning Not thread-safe - programs should be created sequentially
   */
  static uint32_t id_counter_;
};

#endif  // BPFPROGRAM_H_
