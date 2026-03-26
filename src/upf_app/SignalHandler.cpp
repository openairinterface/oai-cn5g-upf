/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SignalHandler.h"
#include <UserPlaneComponent.h>
#include "logger.hpp"

//---------------------------------------------------------------------------------------------------------------
void my_app_signal_handler(int s);

//---------------------------------------------------------------------------------------------------------------
SignalHandler& SignalHandler::getInstance() {
  static SignalHandler sInstance;
  return sInstance;
}

//---------------------------------------------------------------------------------------------------------------
SignalHandler::~SignalHandler() {}

//---------------------------------------------------------------------------------------------------------------
void SignalHandler::enable() {
  signal(SIGINT, SignalHandler::tearDown);
  signal(SIGTERM, SignalHandler::tearDown);
  signal(SIGSEGV, SignalHandler::tearDown);
}

//---------------------------------------------------------------------------------------------------------------
void SignalHandler::tearDown(int signal) {
  Logger::upf_app().info("Signal %d received. Shutting down...", signal);
  UserPlaneComponent::getInstance().tearDown();
  // calling the other tear down routine
  my_app_signal_handler(signal);
  exit(0);
}
