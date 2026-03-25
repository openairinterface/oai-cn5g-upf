/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1 (the "License"); you may not use this
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
 * Changes:     Added map getters for all 7 IP session maps confirmed in
 *              xdp_session_lookup_ip_skel.h. Required by UPF_XDPProgram
 *              GetMapByName() and GetSessionPdrsMap() delegations.
 */
// clang-format on

#ifndef SESSION_LOOKUP_IP_USER_H_
#define SESSION_LOOKUP_IP_USER_H_

#include <ProgramLifeCycle.hpp>
#include <xdp_session_lookup_ip_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"

class BPFMaps;

using SessionLookupIPLifeCycle = ProgramLifeCycle<xdp_session_lookup_ip_kern_c>;

class SessionLookupIPProgram : public BPFProgram {
 public:
  SessionLookupIPProgram();
  virtual ~SessionLookupIPProgram();

  void Load();
  struct bpf_object* GetBpfObject() const;
  struct bpf_program* GetXdpProgram() const;

  /* Map getters -- all 7 IP session maps in this skeleton */
  std::shared_ptr<BPFMap> GetSessionByUeIpMap() const;
  std::shared_ptr<BPFMap> GetSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetRulesMatchMap() const;
  std::shared_ptr<BPFMap> GetSessionQosEnabledMap() const;
  std::shared_ptr<BPFMap> GetFramedRouteMappingMap() const;
  std::shared_ptr<BPFMap> GetFramedRoutingFlagMap() const;
  std::shared_ptr<BPFMap> GetFeatureDispatchMap() const;

 private:
  void InitializeMaps();

  xdp_session_lookup_ip_kern_c* skeleton_ = nullptr;
  std::shared_ptr<SessionLookupIPLifeCycle> lifecycle_;
  std::shared_ptr<BPFMaps> maps_;
};

#endif /* SESSION_LOOKUP_IP_USER_H_ */