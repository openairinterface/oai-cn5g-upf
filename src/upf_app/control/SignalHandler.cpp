/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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
