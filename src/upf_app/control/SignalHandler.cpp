/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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
 * @file SignalHandler.cpp
 * @brief Signal Handler Implementation
 */

#include "SignalHandler.h"
#include "UserPlaneComponent.h"

// Forward declaration
void my_app_signal_handler(int s);

//------------------------------------------------------------------------------
SignalHandler& SignalHandler::GetInstance() {
  static SignalHandler instance;
  return instance;
}

//------------------------------------------------------------------------------
SignalHandler::~SignalHandler() {}

//------------------------------------------------------------------------------
void SignalHandler::Enable() {
  signal(SIGINT, SignalHandler::TearDown);
  signal(SIGTERM, SignalHandler::TearDown);
  signal(SIGSEGV, SignalHandler::TearDown);
}

//------------------------------------------------------------------------------
void SignalHandler::TearDown(int signal) {
  UserPlaneComponent::GetInstance().TearDown();
  // Call the other tear down routine
  my_app_signal_handler(signal);
  exit(0);
}
