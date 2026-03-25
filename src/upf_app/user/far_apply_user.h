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
// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     New file -- FARProgram owns xdp_far_apply skeleton following
 *              the QERProgram pattern (own skeleton + ProgramLifeCycle<T>).
 *              Maps are shared from UPF_XDPProgram primary skeleton via
 *              bpf_map__reuse_fd() before Load() is called.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §8.2.22-26 -- FAR IE
 */
// clang-format on

/**
 * @file  far_apply_user.h
 * @brief Skeleton owner for the FAR (Forwarding Action Rule) XDP program.
 *
 * FARProgram owns the xdp_far_apply_c skeleton and its lifecycle.
 * It does not manage any BPF maps directly -- maps are owned by
 * UPF_XDPProgram (primary skeleton) and shared via reuse_fd().
 *
 * Lifecycle (called by UPF_XDPProgram):
 *   1. Construct    -- opens skeleton
 *   2. UPF_XDPProgram calls ShareMapsFromPrimary(GetBpfObject())
 *   3. Load()       -- loads skeleton (reuses shared map FDs)
 *   4. GetXdpProgram() -- provides program FD for tail_call_progs_map
 *   5. Destructor   -- destroys skeleton
 *
 * 3GPP Ref: 3GPP TS 29.244 V17.10.0 §8.2.22-26 -- Forwarding Action Rule
 */

#ifndef FAR_APPLY_USER_H_
#define FAR_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <xdp_far_apply_skel.h>
#include "BPFProgram.h"
class BPFMap;
class BPFMaps;

using FarProgramLifeCycle = ProgramLifeCycle<xdp_far_apply_kern_c>;

class FARProgram : public BPFProgram {
 public:
  /** @brief Constructor -- opens xdp_far_apply skeleton. */
  FARProgram();
  virtual ~FARProgram();

  /** @brief Load skeleton (call after UPF_XDPProgram has shared maps). */
  void Load();

  /** @brief Return the underlying BPF object (for map sharing). */
  struct bpf_object* GetBpfObject() const;

  /** @brief Return the XDP program pointer (for tail_call_progs_map). */
  struct bpf_program* GetXdpProgram() const;

 private:
  // ==========================================================================
  // Private helpers
  // ==========================================================================
  /**
   * @brief Initialize BPF map wrappers
   */
  void InitializeMaps();

  /**
   * @brief Configure specific BPF maps
   *
   * @param skel Opened BPF skeleton
   * @param upf_cfg Configuration
   */
  void ConfigureFarMaps(struct far_apply_kern_c* skel);

  /**
   * @brief Build FAR ID to PDR mapping
   *
   * Creates internal map for quick PDR lookup by FAR ID.
   *
   * @param pdrs Vector of PDRs
   */
  // void BuildPdrMap(const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs);

  /**
   * @brief Get PDR associated with a FAR ID
   *
   * @param far_id FAR identifier
   * @return std::shared_ptr<pfcp::pfcp_pdr> PDR or nullptr
   */
  // std::shared_ptr<pfcp::pfcp_pdr> GetPdrByFarId(uint32_t far_id) const;

  /** @brief Build a far_map_key from SEID and FAR_ID (pad zeroed). */
  // static far_map_key MakeKey(uint64_t seid, uint32_t far_id);

  /** @brief Translate PFCP URR IE into BPF pfcp_urr struct. */
  // static void ConvertFar(
  //     const pfcp::pfcp_far& pfcp_ie, struct pfcp_far& bpf_far);

  // ==========================================================================
  // Skeleton and lifecycle
  // ==========================================================================
  xdp_far_apply_kern_c* skeleton_ = nullptr;
  std::shared_ptr<FarProgramLifeCycle> lifecycle_;

  // ==========================================================================
  // Maps
  // ==========================================================================
  std::shared_ptr<BPFMaps> maps_;         ///< All BPF maps
  std::shared_ptr<BPFMap> redirect_map_;  ///< redirect map
};

#endif /* FAR_APPLY_USER_H_ */