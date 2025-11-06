/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <signal.h>

class SignalHandler {
 public:
  static SignalHandler& getInstance();
  virtual ~SignalHandler();
  void enable();
  static void tearDown(int signal = SIGTERM);
};
