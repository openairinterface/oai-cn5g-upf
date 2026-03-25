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
 * Changes:     Added map getters for 6 ETH session maps confirmed in
 *              xdp_session_lookup_eth_skel.h.
 */
// clang-format on

#ifndef SESSION_LOOKUP_ETH_USER_H_
#define SESSION_LOOKUP_ETH_USER_H_

#include <ProgramLifeCycle.hpp>
#include <xdp_session_lookup_eth_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"

using SessionLookupETHLifeCycle =
    ProgramLifeCycle<xdp_session_lookup_eth_kern_c>;

class SessionLookupETHProgram : public BPFProgram {
 public:
  SessionLookupETHProgram();
  virtual ~SessionLookupETHProgram();

  void Load();
  struct bpf_object* GetBpfObject() const;
  struct bpf_program* GetXdpProgram() const;

  std::shared_ptr<BPFMap> GetSessionByMacMap() const;
  std::shared_ptr<BPFMap> GetMacPduSessionMap() const;
  std::shared_ptr<BPFMap> GetEthSessionMappingMap() const;
  std::shared_ptr<BPFMap> GetEthSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetEthRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> GetEthEgressIfindexMap() const;

 private:
  xdp_session_lookup_eth_kern_c* skeleton_ = nullptr;
  std::shared_ptr<SessionLookupETHLifeCycle> lifecycle_;
  std::shared_ptr<BPFMaps> maps_;
};

#endif /* SESSION_LOOKUP_ETH_USER_H_ */