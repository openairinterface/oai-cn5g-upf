#include "SignalHandler.h"
#include <UserPlaneComponent.h>

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
  exit(0);
}

/**************************************************************************************************/
