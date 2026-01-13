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
 * @file SignalHandler.cpp
 * @brief Signal Handler Implementation
 * @author OpenAirInterface
 * @date 2025
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
