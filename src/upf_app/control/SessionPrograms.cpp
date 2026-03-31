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
 * @file SessionPrograms.cpp
 * @brief Per-session BPF program and rule state container implementation
 * @author OpenAirInterface
 * @date 2025
 *
 * Key difference from old monolithic architecture:
 *   OLD: SessionPrograms owned a UPF_XDPProgram instance and called
 *        TearDown() on it in the destructor. This was correct when each
 *        session had its own XDP program.
 *
 *   NEW (tail-call): UPF_XDPProgram is the GLOBAL shared pipeline.
 *        All sessions share one pipeline and store per-session state
 *        in BPF maps keyed by SEID. The destructor ONLY cleans up:
 *        1. The per-session QER TC-BPF program (rate shaping)
 *        2. Per-session BPF map entries (URR/BAR/MAR config+state)
 *        3. The rules_enabled entry from session_rules_enabled_map
 */

// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     V17.10.0 boy scout pass — no functional changes in this file.
 *              This file was correct as-is; changes are documentation only:
 *                - Added this changelog block.
 *                - All BPF map cleanup entries (urr_config_map,
 *                  bar_config_map, mar_rules_map) guard-checked against
 *                  rules_enabled_flags — no change needed; already correct.
 *              §-refs used in this file:
 *                §8.2.54  URR ID — urr_config_map / urr_volume_counters_map keyed by SEID
 *                §8.2.57  BAR ID — bar_config_map / bar_state_map keyed by SEID
 *                §8.2.123 MAR ID — mar_rules_map keyed by SEID
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

#include "SessionPrograms.h"
#include <upf_xdp_user.h>
#include <qer_tc_user.h>
#include "rules_enabled_flags.h"
#include "logger.hpp"

// =============================================================================
// Construction / Destruction
// =============================================================================

SessionPrograms::SessionPrograms(
    uint64_t seid, std::shared_ptr<UPF_XDPProgram> upf_xdp_program)
    : seid_(seid),
      upf_xdp_program_(upf_xdp_program),
      qer_program_(nullptr),
      rules_enabled_flags_(0) {
  Logger::upf_app().debug("SessionPrograms created for SEID=0x%016lx", seid_);
}

//------------------------------------------------------------------------------
SessionPrograms::~SessionPrograms() {
  Logger::upf_app().debug(
      "SessionPrograms destroying SEID=0x%016lx (flags=0x%x)", seid_,
      rules_enabled_flags_);

  // 1. Tear down per-session QER TC-BPF program (rate shaping classes)
  //    This removes HTB qdisc classes and TC filters for this session
  if (qer_program_) {
    Logger::upf_app().debug(
        "  Tearing down QER TC-BPF program for SEID=0x%016lx", seid_);
    qer_program_->TearDown();
    qer_program_.reset();
  }

  // 2. Remove per-session BPF map entries for enabled rules
  //    Only cleans up maps for rules that were actually active
  CleanupBpfMapEntries();

  // NOTE: We do NOT call upf_xdp_program_->TearDown().
  // The XDP pipeline is the global shared resource managed by
  // UserPlaneComponent. It outlives all sessions.
  upf_xdp_program_.reset();

  Logger::upf_app().debug("SessionPrograms destroyed for SEID=0x%016lx", seid_);
}

// =============================================================================
// Identity
// =============================================================================

uint64_t SessionPrograms::GetSeid() const {
  return seid_;
}

// =============================================================================
// Pipeline Access
// =============================================================================

std::shared_ptr<UPF_XDPProgram> SessionPrograms::GetPipelineProgram() const {
  return upf_xdp_program_;
}

// =============================================================================
// QER Program (per-session TC-BPF)
// =============================================================================

void SessionPrograms::SetQERProgram(std::shared_ptr<QERTCProgram> qer_program) {
  qer_program_ = qer_program;
}

//------------------------------------------------------------------------------
std::shared_ptr<QERTCProgram> SessionPrograms::GetQERProgram() const {
  return qer_program_;
}

//------------------------------------------------------------------------------
bool SessionPrograms::HasQERProgram() const {
  return qer_program_ != nullptr;
}

// =============================================================================
// Rule Enable Flags
// =============================================================================

void SessionPrograms::SetRulesEnabledFlags(uint32_t flags) {
  rules_enabled_flags_ = flags;
}

//------------------------------------------------------------------------------
uint32_t SessionPrograms::GetRulesEnabledFlags() const {
  return rules_enabled_flags_;
}

//------------------------------------------------------------------------------
bool SessionPrograms::IsRuleEnabled(uint32_t flag) const {
  return (rules_enabled_flags_ & flag) != 0;
}

//------------------------------------------------------------------------------
bool SessionPrograms::IsQEREnabled() const {
  return IsRuleEnabled(RULE_QER_ENABLED);
}

//------------------------------------------------------------------------------
bool SessionPrograms::IsURREnabled() const {
  return IsRuleEnabled(RULE_URR_ENABLED);
}

//------------------------------------------------------------------------------
bool SessionPrograms::IsBAREnabled() const {
  return IsRuleEnabled(RULE_BAR_ENABLED);
}

//------------------------------------------------------------------------------
bool SessionPrograms::IsMAREnabled() const {
  return IsRuleEnabled(RULE_MAR_ENABLED);
}

// =============================================================================
// Internal BPF Map Cleanup
// =============================================================================

void SessionPrograms::CleanupBpfMapEntries() {
  if (!upf_xdp_program_) {
    Logger::upf_app().warn(
        "  No pipeline reference for BPF cleanup SEID=0x%016lx", seid_);
    return;
  }

  // --- URR maps (config + volume counters) ---
  if (IsURREnabled()) {
    auto urr_cfg_map = upf_xdp_program_->GetMapByName("urr_config_map");
    if (urr_cfg_map) {
      urr_cfg_map->Remove(seid_);
      Logger::upf_app().debug(
          "  Removed urr_config_map entry for SEID=0x%016lx", seid_);
    }

    auto urr_vol_map =
        upf_xdp_program_->GetMapByName("urr_volume_counters_map");
    if (urr_vol_map) {
      urr_vol_map->Remove(seid_);
      Logger::upf_app().debug(
          "  Removed urr_volume_counters_map entry for SEID=0x%016lx", seid_);
    }
  }

  // --- BAR maps (config + runtime buffering state) ---
  if (IsBAREnabled()) {
    auto bar_cfg_map = upf_xdp_program_->GetMapByName("bar_config_map");
    if (bar_cfg_map) {
      bar_cfg_map->Remove(seid_);
      Logger::upf_app().debug(
          "  Removed bar_config_map entry for SEID=0x%016lx", seid_);
    }

    auto bar_st_map = upf_xdp_program_->GetMapByName("bar_state_map");
    if (bar_st_map) {
      bar_st_map->Remove(seid_);
      Logger::upf_app().debug(
          "  Removed bar_state_map entry for SEID=0x%016lx", seid_);
    }
  }

  // --- MAR rules map ---
  if (IsMAREnabled()) {
    auto mar_map = upf_xdp_program_->GetMapByName("mar_rules_map");
    if (mar_map) {
      mar_map->Remove(seid_);
      Logger::upf_app().debug(
          "  Removed mar_rules_map entry for SEID=0x%016lx", seid_);
    }
  }

  // --- Session rules_enabled bitmask (always present for active sessions) ---
  auto rules_map = upf_xdp_program_->GetMapByName("session_rules_enabled_map");
  if (rules_map) {
    rules_map->Remove(seid_);
    Logger::upf_app().debug(
        "  Removed session_rules_enabled_map entry for SEID=0x%016lx", seid_);
  }
}
