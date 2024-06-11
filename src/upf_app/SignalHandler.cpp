#include "SignalHandler.h"
#include <UserPlaneComponent.h>

void my_app_signal_handler(int s);

/**************************************************************************************************/
SignalHandler& SignalHandler::getInstance() {
  static SignalHandler sInstance;
  return sInstance;
}

/**************************************************************************************************/
SignalHandler::~SignalHandler() {}

/**************************************************************************************************/
void SignalHandler::enable() {
  signal(SIGINT, SignalHandler::tearDown);
  signal(SIGTERM, SignalHandler::tearDown);
  signal(SIGSEGV, SignalHandler::tearDown);
}

/**************************************************************************************************/
void SignalHandler::tearDown(int signal) {
  UserPlaneComponent::getInstance().tearDown();
  // calling the other tear down routine
  my_app_signal_handler(signal);
  exit(0);
}

/**************************************************************************************************/
