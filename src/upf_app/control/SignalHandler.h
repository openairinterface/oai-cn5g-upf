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
 * Changes:     Boy Scout — no §-ref corrections needed (no PFCP §-refs in
 *              this file); @date normalised.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/**
 * @file SignalHandler.h
 * @brief Signal Handler for Graceful Shutdown
 * @author OpenAirInterface
 * @date 2025
 *
 * Handles system signals (SIGINT, SIGTERM, SIGSEGV) for graceful shutdown
 * of the UPF component.
 */

#ifndef SIGNAL_HANDLER_H_
#define SIGNAL_HANDLER_H_

#include <signal.h>

// clang-format off
 /* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
  * Date:        2026-03
  * Changes:     Boy Scout — no §-ref corrections needed (no PFCP §-refs in
  *              this file); @date normalised.
  * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
  */
// clang-format on

/**
 * @class SignalHandler
 * @brief Manages system signals for graceful shutdown
 *
 * Registers handlers for:
 * - SIGINT (Ctrl+C)
 * - SIGTERM (termination request)
 * - SIGSEGV (segmentation fault)
 *
 * @note Follows Google C++ Style Guide
 */
class SignalHandler {
 public:
  /**
   * @brief Get singleton instance
   * @return Reference to singleton instance
   */
  static SignalHandler& GetInstance();

  /**
   * @brief Destructor
   */
  virtual ~SignalHandler();

  /**
   * @brief Enable signal handling
   *
   * Registers signal handlers for SIGINT, SIGTERM, and SIGSEGV.
   */
  void Enable();

  /**
   * @brief Trigger teardown on signal
   *
   * Performs graceful shutdown by calling UserPlaneComponent::TearDown()
   * and other cleanup routines.
   *
   * @param signal Signal number (default: SIGTERM)
   */
  static void TearDown(int signal = SIGTERM);

 private:
  /**
   * @brief Private constructor for singleton
   */
  SignalHandler() = default;
};

#endif  // SIGNAL_HANDLER_H_
