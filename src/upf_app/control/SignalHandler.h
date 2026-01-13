/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file SignalHandler.h
 * @brief Signal Handler for Graceful Shutdown
 *
 * Handles system signals (SIGINT, SIGTERM, SIGSEGV) for graceful shutdown
 * of the UPF component.
 */

#ifndef SIGNAL_HANDLER_H_
#define SIGNAL_HANDLER_H_

#include <signal.h>

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
