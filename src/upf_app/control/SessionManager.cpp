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
 * @file SessionManager.cpp
 * @brief PFCP Session Manager Implementation
 * @author OpenAirInterface
 * @date 2025
 *
 * Implements complete CRUD operations for PFCP sessions, PDRs, FARs, and QERs
 * according to 3GPP TS 29.244 V17.10.0 specifications.
 *
 * @par Changelog
 * | Date       | Author | Description                                        |
 * |------------|--------|----------------------------------------------------|
 * | 2025-xx-xx | OAI    | Initial implementation                             |
 * | 2026-03-11 | OAI    | Harmonised §-refs to TS 29.244 V17.10.0; fixed     |
 * |            |        | missing lock in UpdateSession (TODO); removed      |
 * |            |        | duplicate urr_id update and double updated_count++ |
 * |            |        | in HandlePdrUpdates; fixed §8.2.50→§8.2.100 in     |
 * |            |        | HandleBarUpdates; corrected OHC §-ref comment.     |
 * | 2026-03-11 | OAI    | Bug fixes (functional):                            |
 * |            |        | HandleUrrUpdates: added measurement_method,        |
 * |            |        |   time_quota, quota_holding_time, linked_urr_id    |
 * |            |        |   (all absent from previous implementation).       |
 * |            |        | HandleBarUpdates: field name wrong —               |
 * |            |        |   dl_buffering_suggested_packet_count renamed to   |
 * |            |        | downlink_data_notification_delay in pfcp_bar.hpp;  |
 * |            |        | fixed to write correct field.                      |
 * |            |        | HandleMarUpdates: added steering_functionality     |
 * |            |        | (§8.2.124); AFAI now copies weight (§8.2.126),     |
 * |            |        | priority (§8.2.127), urr_id (§8.2.54) in addition  |
 * |            |        | to far_id; shared lambda used for both AFAI paths. |
 * |            |        | All Section x.y refs → §x.y procedure refs.        |
 */

#include "SessionManager.h"
#include "SessionProgramManager.h"
#include <upf_xdp_user.h>
#include <algorithm>
#include <inttypes.h>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_config.hpp"
#include "pfcp_session.hpp"
#include "pfcp_pdr.hpp"
#include "pfcp_far.hpp"
#include "pfcp_qer.hpp"
#include "pfcp_urr.hpp"
#include "pfcp_bar.hpp"
#include "pfcp_mar.hpp"
#include "itti_msg_n4.hpp"
#include "pfcp_switch.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

extern oai::upf::app::pfcp_switch*
    pfcp_switch_inst;  // defined in pfcp_switch.cpp

//------------------------------------------------------------------------------
// Constructors & Destructor
//------------------------------------------------------------------------------
SessionManager::SessionManager() {}

//------------------------------------------------------------------------------
SessionManager::SessionManager(
    std::shared_ptr<SessionProgramManager> session_program_manager)
    : session_program_manager_(session_program_manager) {
  if (!session_program_manager) {
    throw std::invalid_argument(
        "Session Manager: program_manager cannot be null");
  }

  Logger::upf_app().debug("Session Manager initialized");
}

//------------------------------------------------------------------------------
SessionManager::~SessionManager() {
  std::lock_guard<std::mutex> lock(sessions_mutex_);
  sessions_.clear();
  seid_to_session_.clear();
  Logger::upf_app().debug("Session Manager destroyed");
}

//------------------------------------------------------------------------------
// Session Lifecycle Management
// Reference: 3GPP TS 29.244 V17.10.0 §7.5 — Session
// establishment/modification/deletion
//------------------------------------------------------------------------------

SessionOperationResult SessionManager::CreateSession(
    std::shared_ptr<pfcp::pfcp_session> session) {
  if (!session) {
    Logger::upf_app().error(
        "[N4] Create Session: Invalid session pointer (null)");
    return SessionOperationResult(false, "Invalid session pointer", 0);
  }

  uint64_t seid = session->get_up_seid();
  Logger::upf_app().debug(
      "[N4] Create session: seid " SEID_FMT " - Validating session context",
      seid);

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    // Check if session already exists
    if (seid_to_session_.find(seid) != seid_to_session_.end()) {
      Logger::upf_app().error(
          "[N4] Create Session: seid " SEID_FMT
          "- Session already exists in registry",
          seid);
      return SessionOperationResult(false, "Session already exists", seid);
    }

    // Store session
    sessions_.push_back(session);
    seid_to_session_[seid] = session;

    // Categorize and sort PDRs by §8.2.11 Precedence (Tables 7.5.2.2-1
    // / 7.5.4.2-1)
    CategorizePdrs(session);
    SortPdrs(session->pdrs_uplink);
    SortPdrs(session->pdrs_downlink);

    // Log session creation (TEIDs are per-PDR/FAR, not per-session)
    Logger::upf_app().debug(
        "[N4] Create Session: seid " SEID_FMT
        " - Creating eBPF data-path pipeline",
        seid);

    // Log uplink PDRs and their TEIDs
    if (!session->pdrs_uplink.empty()) {
      Logger::upf_app().debug(
          "  → Uplink PDRs (%zu rules):", session->pdrs_uplink.size());

      for (const auto& pdr : session->pdrs_uplink) {
        uint32_t teid_ul = GetUplinkTeidFromPdr(pdr);
        uint16_t pdr_id  = pdr->pdr_id.rule_id;

        if (teid_ul != 0) {
          Logger::upf_app().debug(
              "    • PDR %u: Local F-TEID " TEID_FMT " (UPF listens on N3)",
              pdr_id, teid_ul);
        } else {
          Logger::upf_app().warn(
              "    • PDR %u: No F-TEID found (possible configuration issue)",
              pdr_id);
        }
      }
    }
    // Log downlink PDRs and their associated FAR TEIDs
    if (!session->pdrs_downlink.empty()) {
      Logger::upf_app().debug(
          "  → Downlink PDRs (%zu rules):", session->pdrs_downlink.size());

      for (const auto& pdr : session->pdrs_downlink) {
        uint16_t pdr_id = pdr->pdr_id.rule_id;

        // Get associated FAR
        std::shared_ptr<pfcp::pfcp_far> far;
        if (GetFarForPdr(session, pdr, far)) {
          uint32_t far_id = far->far_id.far_id;
          uint32_t teid   = GetDownlinkTeidFromFar(far);

          if (teid != 0) {
            Logger::upf_app().debug(
                "    • PDR %u → FAR %u: Remote F-TEID " TEID_FMT
                " (send to gNB on N3)",
                pdr_id, far_id, teid);
          } else {
            Logger::upf_app().debug(
                "    • PDR %u → FAR %u: No GTP-U encapsulation (forwarding to "
                "N6)",
                pdr_id, far_id);
          }
        } else {
          Logger::upf_app().warn(
              "    • PDR %u: No associated FAR found", pdr_id);
        }
      }
    }

    // Create BPF pipeline
    session_program_manager_->CreatePipeline(session);

    Logger::upf_app().info(
        "[N4] Create Session: seid 0x%lx - eBPF data-path pipeline created "
        "successfully",
        seid);
    return SessionOperationResult(true, "Session created", seid);

  } catch (const std::exception& e) {
    Logger::upf_app().error(
        "[N4] Create Session: seid 0x%lx - Exception: %s", seid, e.what());
    return SessionOperationResult(
        false, std::string("Exception: ") + e.what(), seid);
  }
}

//------------------------------------------------------------------------------
SessionOperationResult SessionManager::UpdateSession(
    std::shared_ptr<pfcp::pfcp_session> session) {
  if (!session) {
    Logger::upf_app().error(
        "[N4] Update Session: Invalid session pointer (null)");
    return SessionOperationResult(false, "Invalid session pointer", 0);
  }

  uint64_t seid = session->get_up_seid();

  // TODO(thread-safety): UpdateSession does NOT acquire sessions_mutex_ here.
  // When called directly it is therefore not thread-safe.  When called from
  // ModifySession the caller already holds sessions_mutex_, so adding a
  // std::lock_guard here would deadlock.  Refactor: add UpdateSessionUnlocked()
  // for the ModifySession call-site, and lock here for the public path.
  try {
    // Find existing session
    auto it = seid_to_session_.find(seid);
    if (it == seid_to_session_.end()) {
      Logger::upf_app().error(
          "[N4] Update Session: seid " SEID_FMT " - Session not found", seid);
      return SessionOperationResult(false, "Session not found", seid);
    }

    // Update session reference
    it->second = session;

    // Recategorize and sort PDRs
    CategorizePdrs(session);
    SortPdrs(session->pdrs_uplink);
    SortPdrs(session->pdrs_downlink);

    Logger::upf_app().debug(
        "[N4] Update Session: seid " SEID_FMT
        " - Modifying eBPF data-path pipeline",
        seid);

    // uint32_t teid_dl = RetrieveDownlinkTeid(session);
    // uint32_t teid_ul = FindUplinkTeid(seid);

    // Log updated PDR/FAR rules
    if (!session->pdrs_uplink.empty()) {
      Logger::upf_app().debug(
          "  → Updated Uplink PDRs (%zu rules):", session->pdrs_uplink.size());

      for (const auto& pdr : session->pdrs_uplink) {
        uint32_t teid   = GetUplinkTeidFromPdr(pdr);
        uint16_t pdr_id = pdr->pdr_id.rule_id;

        if (teid != 0) {
          Logger::upf_app().debug(
              "    • PDR %u: F-TEID " TEID_FMT, pdr_id, teid);
        }
      }
    }

    if (!session->pdrs_downlink.empty()) {
      Logger::upf_app().debug(
          "  → Updated Downlink PDRs (%zu rules):",
          session->pdrs_downlink.size());

      for (const auto& pdr : session->pdrs_downlink) {
        uint16_t pdr_id = pdr->pdr_id.rule_id;
        std::shared_ptr<pfcp::pfcp_far> far;

        if (GetFarForPdr(session, pdr, far)) {
          uint32_t teid   = GetDownlinkTeidFromFar(far);
          uint32_t far_id = far->far_id.far_id;

          if (teid != 0) {
            Logger::upf_app().debug(
                "    • PDR %u → FAR %u: TEID " TEID_FMT, pdr_id, far_id, teid);
          }
        }
      }
    }

    // Modify BPF pipeline (pass the entire session, not individual TEIDs)
    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info(
        "[N4] Update Session: seid " SEID_FMT
        " - eBPF data-path pipeline updated successfully",
        seid);

    return SessionOperationResult(true, "Session updated", seid);

  } catch (const std::exception& e) {
    Logger::upf_app().error(
        "[N4] Update Session: seid " SEID_FMT " - Exception: %s", seid,
        e.what());
    return SessionOperationResult(false, e.what(), seid);
  }
}
//------------------------------------------------------------------------------
SessionOperationResult SessionManager::DeleteSession(uint64_t seid) {
  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto it = seid_to_session_.find(seid);
    if (it == seid_to_session_.end()) {
      Logger::upf_app().warn(
          "[N4] Delete Session: seid " SEID_FMT "-Session not found", seid);
      return SessionOperationResult(false, "Session not found", seid);
    }

    auto session = it->second;

    // Log deletion with PDR/FAR details
    Logger::upf_app().debug(
        "[N4] Delete Session: seid " SEID_FMT
        " - Deleting eBPF data-path pipeline",
        seid);

    // Log what's being deleted
    int uplink_pdrs   = session->pdrs_uplink.size();
    int downlink_pdrs = session->pdrs_downlink.size();
    int total_pdrs    = session->pdrs.size();
    int total_fars    = session->fars.size();
    int total_qers    = session->qers.size();

    Logger::upf_app().debug(
        "  → Removing: %d PDR(s) (%d UL, %d DL), %d FAR(s), %d QER(s)",
        total_pdrs, uplink_pdrs, downlink_pdrs, total_fars, total_qers);

    // Log TEIDs being removed (for debugging)
    for (const auto& pdr : session->pdrs_uplink) {
      uint32_t teid = GetUplinkTeidFromPdr(pdr);
      if (teid != 0) {
        Logger::upf_app().debug(
            "    • Removing uplink TEID " TEID_FMT " (PDR %u)", teid,
            pdr->pdr_id.rule_id);
      }
    }

    for (const auto& pdr : session->pdrs_downlink) {
      std::shared_ptr<pfcp::pfcp_far> far;
      if (GetFarForPdr(session, pdr, far)) {
        uint32_t teid = GetDownlinkTeidFromFar(far);
        if (teid != 0) {
          Logger::upf_app().debug(
              "    • Removing downlink TEID " TEID_FMT " (PDR %u → FAR %u)",
              teid, pdr->pdr_id.rule_id, far->far_id.far_id);
        }
      }
    }

    // Remove from BPF pipeline
    Logger::upf_app().info(
        "[eBPF] Remove Pipeline - Cleaning up pipeline for session " SEID_FMT,
        seid);

    session_program_manager_->RemovePipeline(seid);

    Logger::upf_app().info(
        "[N4] Delete Session: seid " SEID_FMT
        " - eBPF data-path pipeline deleted successfully",
        seid);

    // Remove from maps
    seid_to_session_.erase(it);

    // Remove from vector
    sessions_.erase(
        std::remove_if(
            sessions_.begin(), sessions_.end(),
            [seid](const std::shared_ptr<pfcp::pfcp_session>& s) {
              return s->get_up_seid() == seid;
            }),
        sessions_.end());

    Logger::upf_app().info(
        "[N4] Delete Session: seid " SEID_FMT
        " - Session removed from registry",
        seid);

    return SessionOperationResult(true, "Session deleted", seid);

  } catch (const std::exception& e) {
    Logger::upf_app().error(
        "[N4] Delete Session: seid " SEID_FMT " - Exception: %s", seid,
        e.what());
    return SessionOperationResult(
        false, std::string("Exception: ") + e.what(), seid);
  }
}

//------------------------------------------------------------------------------
std::shared_ptr<pfcp::pfcp_session> SessionManager::GetSession(
    uint64_t seid) const {
  std::lock_guard<std::mutex> lock(sessions_mutex_);
  auto it = seid_to_session_.find(seid);
  return (it != seid_to_session_.end()) ? it->second : nullptr;
}

//------------------------------------------------------------------------------
// Non-locking variant: caller must hold sessions_mutex_
std::shared_ptr<pfcp::pfcp_session> SessionManager::GetSessionUnlocked(
    uint64_t seid) const {
  auto it = seid_to_session_.find(seid);
  return (it != seid_to_session_.end()) ? it->second : nullptr;
}

//------------------------------------------------------------------------------
std::vector<std::shared_ptr<pfcp::pfcp_session>>
SessionManager::GetAllSessions() const {
  std::lock_guard<std::mutex> lock(sessions_mutex_);
  return sessions_;
}

//------------------------------------------------------------------------------
// N4 Message Handlers
// Reference: 3GPP TS 29.244 V17.10.0 §7.5.4 — PFCP Session Modification
//------------------------------------------------------------------------------

SessionOperationResult SessionManager::EstablishSession(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  // Logger::upf_app().error(
  //     "EstablishSession START: this=%p, session_program_manager_=%p,
  //     xdp_program_=%p", (void*) this, (void*) session_program_manager_.get(),
  //     (void*) xdp_program_.get());
  uint64_t seid = session->get_up_seid();
  Logger::upf_app().debug("Establish Session seid " SEID_FMT, seid);

  if (session->pdrs.empty()) {
    Logger::upf_app().error("No PDRs found in session " SEID_FMT, seid);
    return SessionOperationResult(false, "No PDRs in session", seid);
  }

  return CreateSession(session);
}

//------------------------------------------------------------------------------
// 3GPP TS 29.244 V17.10.0 §7.5.4 — PFCP Session Modification Request
SessionOperationResult SessionManager::ModifySession(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  if (!mod_req) {
    return SessionOperationResult(false, "Modification request is null", 0);
  }

  uint64_t seid = session->get_up_seid();
  Logger::upf_app().debug("ModifySession() seid " SEID_FMT, seid);

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto it = seid_to_session_.find(seid);
    if (it == seid_to_session_.end()) {
      return SessionOperationResult(false, "Session not found", seid);
    }

    // Create PDR/FAR/QER/URR/BAR/MAR (§7.5.2 grouped IEs)
    // (already done in pfcp_switch)
    // if (!mod_req->pfcp_ies.create_pdrs.empty())
    // {
    //   Logger::upf_app().debug(
    //       "Adding %zu new PDRs", mod_req->pfcp_ies.create_pdrs.size());
    //   for (const auto& pdr : mod_req->pfcp_ies.create_pdrs) {
    //     session->pdrs.push_back(std::make_shared<pfcp::pfcp_pdr>(pdr));
    //   }
    // }

    // if (!mod_req->pfcp_ies.create_fars.empty()) {
    //   Logger::upf_app().debug(
    //       "Adding %zu new FARs", mod_req->pfcp_ies.create_fars.size());
    //   for (const auto& far : mod_req->pfcp_ies.create_fars) {
    //     session->fars.push_back(std::make_shared<pfcp::pfcp_far>(far));
    //   }
    // }

    // if (!mod_req->pfcp_ies.create_qers.empty()) {
    //   Logger::upf_app().debug(
    //       "Adding %zu new QERs", mod_req->pfcp_ies.create_qers.size());
    //   for (const auto& qer : mod_req->pfcp_ies.create_qers) {
    //     session->qers.push_back(std::make_shared<pfcp::pfcp_qer>(qer));
    //   }
    // }

    // Update PDR/FAR/QER/URR/BAR/MAR (§7.5.4 grouped IEs)
    //                                              8.2.12, 8.2.13, 8.2.14)
    size_t updated_pdrs = HandlePdrUpdates(session, mod_req);
    size_t updated_fars = HandleFarUpdates(session, mod_req);
    size_t updated_qers = HandleQerUpdates(session, mod_req);
    size_t updated_urrs = HandleUrrUpdates(session, mod_req);
    size_t updated_bars = HandleBarUpdates(session, mod_req);
    size_t updated_mars = HandleMarUpdates(session, mod_req);

    // Remove PDR/FAR/QER/URR/BAR/MAR (§7.5.4 grouped IEs)
    size_t removed_pdrs = HandlePdrRemoval(session, mod_req);
    size_t removed_fars = HandleFarRemoval(session, mod_req);
    size_t removed_qers = HandleQerRemoval(session, mod_req);
    size_t removed_urrs = HandleUrrRemoval(session, mod_req);
    size_t removed_bars = HandleBarRemoval(session, mod_req);
    size_t removed_mars = HandleMarRemoval(session, mod_req);

    Logger::upf_app().info("[N4] Session Modification: seid 0x%lx", seid);

    // Show created rules (handled by pfcp_switch before reaching here)
    const size_t n_create_pdrs = mod_req->pfcp_ies.create_pdrs.size();
    const size_t n_create_fars = mod_req->pfcp_ies.create_fars.size();
    const size_t n_create_qers = mod_req->pfcp_ies.create_qers.size();
    const size_t n_create_urrs = mod_req->pfcp_ies.create_urrs.size();
    const size_t n_create_bars = mod_req->pfcp_ies.create_bars.size();
    const size_t n_create_mars = mod_req->pfcp_ies.create_mars.size();

    if (n_create_pdrs || n_create_fars || n_create_qers || n_create_urrs ||
        n_create_bars || n_create_mars) {
      Logger::upf_app().info(
          "  └─ Created: %zu PDR, %zu FAR, %zu QER, %zu URR, %zu BAR, %zu MAR",
          n_create_pdrs, n_create_fars, n_create_qers, n_create_urrs,
          n_create_bars, n_create_mars);
    }

    // Show updated rules
    if (updated_pdrs || updated_fars || updated_qers || updated_urrs ||
        updated_bars || updated_mars) {
      Logger::upf_app().info(
          "  └─ Updated: %zu PDR, %zu FAR, %zu QER, %zu URR, %zu BAR, %zu MAR",
          updated_pdrs, updated_fars, updated_qers, updated_urrs, updated_bars,
          updated_mars);
    }

    // Show removed rules
    if (removed_pdrs || removed_fars || removed_qers || removed_urrs ||
        removed_bars || removed_mars) {
      Logger::upf_app().info(
          "  └─ Removed: %zu PDR, %zu FAR, %zu QER, %zu URR, %zu BAR, %zu MAR",
          removed_pdrs, removed_fars, removed_qers, removed_urrs, removed_bars,
          removed_mars);
    }
    // Update the session
    Logger::upf_app().debug(
        "[N4] Session Modification: seid 0x%lx - Applying pipeline updates",
        seid);

    auto result = UpdateSession(session);

    if (result.success) {
      Logger::upf_app().info(
          "[N4] Session Modification: seid 0x%lx - "
          "Completed successfully [Status: %s]",
          seid, result.message.c_str());
    } else {
      Logger::upf_app().error(
          "[N4] Session Modification: seid 0x%lx - "
          "Failed [Reason: %s]",
          seid, result.message.c_str());
    }

    return result;

  } catch (const std::exception& e) {
    Logger::upf_app().error(
        "Failed to modify session " SEID_FMT ": %s", seid, e.what());
    return SessionOperationResult(
        false, std::string("Exception: ") + e.what(), seid);
  }
}
//------------------------------------------------------------------------------
// 3GPP TS 29.244 V17.10.0 §7.5.6 — PFCP Session Deletion Request
SessionOperationResult SessionManager::RemoveSession(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  uint64_t seid = session->get_up_seid();
  Logger::upf_app().info("RemoveSession() seid " SEID_FMT, seid);

  return DeleteSession(seid);
}

//------------------------------------------------------------------------------
// PDR Management - CRUD Operations
// PDR Management — §7.5.2.2 Create PDR / §7.5.4.2 Update PDR / §7.5.4.6 Remove
// PDR
//------------------------------------------------------------------------------

// §7.5.2.2 Create PDR — Table 7.5.2.2-1
bool SessionManager::AddPdr(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_pdr> pdr) {
  if (!pdr) {
    Logger::upf_app().error("AddPdr: null PDR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error("AddPdr: session " SEID_FMT " not found", seid);
      return false;
    }

    // Add PDR to session
    session->pdrs.push_back(pdr);

    // Re-categorize and sort by precedence
    CategorizePdrs(session);
    SortPdrs(session->pdrs_uplink);
    SortPdrs(session->pdrs_downlink);

    // Update BPF maps
    session_program_manager_->CreatePipeline(session);

    Logger::upf_app().info(
        "Added PDR %u to session " SEID_FMT, pdr->pdr_id.rule_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("AddPdr failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.2 Update PDR — Table 7.5.4.2-1
bool SessionManager::UpdatePdr(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_pdr> pdr) {
  if (!pdr) {
    Logger::upf_app().error("UpdatePdr: null PDR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "UpdatePdr: session " SEID_FMT " not found", seid);
      return false;
    }

    // Find and update PDR
    uint16_t pdr_id = pdr->pdr_id.rule_id;
    bool found      = false;

    for (auto& existing_pdr : session->pdrs) {
      if (existing_pdr->pdr_id.rule_id == pdr_id) {
        existing_pdr = pdr;
        found        = true;
        break;
      }
    }

    if (!found) {
      Logger::upf_app().error(
          "UpdatePdr: PDR %u not found in session " SEID_FMT, pdr_id, seid);
      return false;
    }

    // Re-categorize and update BPF maps
    CategorizePdrs(session);
    SortPdrs(session->pdrs_uplink);
    SortPdrs(session->pdrs_downlink);
    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info("Updated PDR %u in session " SEID_FMT, pdr_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("UpdatePdr failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.6 Remove PDR — Table 7.5.4.6-1
bool SessionManager::RemovePdr(uint64_t seid, uint16_t pdr_id) {
  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "RemovePdr: session " SEID_FMT " not found", seid);
      return false;
    }

    // Remove PDR from all lists
    auto remove_from = [pdr_id](auto& vec) {
      vec.erase(
          std::remove_if(
              vec.begin(), vec.end(),
              [pdr_id](const auto& p) { return p->pdr_id.rule_id == pdr_id; }),
          vec.end());
    };

    remove_from(session->pdrs);
    remove_from(session->pdrs_uplink);
    remove_from(session->pdrs_downlink);

    // Update BPF maps
    SortPdrs(session->pdrs_uplink);
    SortPdrs(session->pdrs_downlink);
    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info(
        "Removed PDR %u from session " SEID_FMT, pdr_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("RemovePdr failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// FAR Management - CRUD Operations
// FAR Management — §7.5.2.3 Create FAR / §7.5.4.3 Update FAR / §7.5.4.7 Remove
// FAR
//------------------------------------------------------------------------------

// §7.5.2.3 Create FAR — Table 7.5.2.3-1
bool SessionManager::AddFar(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_far> far) {
  if (!far) {
    Logger::upf_app().error("AddFar: null FAR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error("AddFar: session " SEID_FMT " not found", seid);
      return false;
    }

    session->fars.push_back(far);

    // Update BPF maps
    session_program_manager_->CreatePipeline(session);

    Logger::upf_app().info(
        "Added FAR %u to session " SEID_FMT, far->far_id.far_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("AddFar failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.3 Update FAR — Table 7.5.4.3-1
bool SessionManager::UpdateFar(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_far> far) {
  if (!far) {
    Logger::upf_app().error("UpdateFar: null FAR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "UpdateFar: session " SEID_FMT " not found", seid);
      return false;
    }

    // Find and update FAR
    uint32_t far_id = far->far_id.far_id;
    bool found      = false;

    for (auto& existing_far : session->fars) {
      if (existing_far->far_id.far_id == far_id) {
        existing_far = far;
        found        = true;
        break;
      }
    }

    if (!found) {
      Logger::upf_app().error(
          "UpdateFar: FAR %u not found in session " SEID_FMT, far_id, seid);
      return false;
    }

    // Update BPF maps
    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info("Updated FAR %u in session " SEID_FMT, far_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("UpdateFar failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.7 Remove FAR — Table 7.5.4.7-1
bool SessionManager::RemoveFar(uint64_t seid, uint32_t far_id) {
  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "RemoveFar: session " SEID_FMT " not found", seid);
      return false;
    }

    // Remove FAR
    session->fars.erase(
        std::remove_if(
            session->fars.begin(), session->fars.end(),
            [far_id](const auto& f) { return f->far_id.far_id == far_id; }),
        session->fars.end());

    // Update BPF maps
    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info(
        "Removed FAR %u from session " SEID_FMT, far_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("RemoveFar failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// QER Management - CRUD Operations
// QER Management — §7.5.2.5 Create QER / §7.5.4.5 Update QER / §7.5.4.9 Remove
// QER
//------------------------------------------------------------------------------

// §7.5.2.5 Create QER — Table 7.5.2.5-1
bool SessionManager::AddQer(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_qer> qer) {
  if (!qer) {
    Logger::upf_app().error("AddQer: null QER");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error("AddQer: session " SEID_FMT " not found", seid);
      return false;
    }

    session->qers.push_back(qer);

    // Re-categorize to update uplink/downlink QERs
    CategorizePdrs(session);

    // Update BPF maps
    session_program_manager_->CreatePipeline(session);

    Logger::upf_app().info(
        "Added QER %u to session " SEID_FMT, qer->qer_id.second.qer_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("AddQer failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.5 Update QER — Table 7.5.4.5-1
bool SessionManager::UpdateQer(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_qer> qer) {
  if (!qer) {
    Logger::upf_app().error("UpdateQer: null QER");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "UpdateQer: session " SEID_FMT " not found", seid);
      return false;
    }

    // Find and update QER
    uint32_t qer_id = qer->qer_id.second.qer_id;
    bool found      = false;

    for (auto& existing_qer : session->qers) {
      if (existing_qer->qer_id.second.qer_id == qer_id) {
        existing_qer = qer;
        found        = true;
        break;
      }
    }

    if (!found) {
      Logger::upf_app().error(
          "UpdateQer: QER %u not found in session " SEID_FMT, qer_id, seid);
      return false;
    }

    // Re-categorize and update BPF maps
    CategorizePdrs(session);
    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info("Updated QER %u in session " SEID_FMT, qer_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("UpdateQer failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.9 Remove QER — Table 7.5.4.9-1
bool SessionManager::RemoveQer(uint64_t seid, uint32_t qer_id) {
  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "RemoveQer: session " SEID_FMT " not found", seid);
      return false;
    }

    // Remove QER from all lists
    auto remove_from = [qer_id](auto& vec) {
      vec.erase(
          std::remove_if(
              vec.begin(), vec.end(),
              [qer_id](const auto& q) {
                return q->qer_id.second.qer_id == qer_id;
              }),
          vec.end());
    };

    remove_from(session->qers);
    remove_from(session->qers_uplink);
    remove_from(session->qers_downlink);

    // Update BPF maps
    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info(
        "Removed QER %u from session " SEID_FMT, qer_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("RemoveQer failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// Helper Methods
//------------------------------------------------------------------------------

bool SessionManager::GetFarForPdr(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_far>& out_far) const {
  pfcp::far_id_t far_id;
  return (pdr->get(far_id) && session->get(far_id.far_id, out_far));
}

//------------------------------------------------------------------------------
bool SessionManager::GetQerForPdr(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_qer>& out_qer) const {
  pfcp::qer_id_t qer_id;
  return (pdr->get(qer_id) && session->get(qer_id.qer_id, out_qer));
}

//------------------------------------------------------------------------------
std::shared_ptr<pfcp::pfcp_qer> SessionManager::FindQer(
    std::shared_ptr<pfcp::pfcp_session> session, uint32_t qer_id) const {
  for (auto& qer : session->qers) {
    if (qer->qer_id.second.qer_id == qer_id) {
      return qer;
    }
  }
  return nullptr;
}

//------------------------------------------------------------------------------
// Extract uplink TEID directly from PDR (§8.2.3 — F-TEID).
// This gets the local F-TEID that the UPF listens on for uplink traffic.
//------------------------------------------------------------------------------
uint32_t SessionManager::GetUplinkTeidFromPdr(
    std::shared_ptr<pfcp::pfcp_pdr> pdr) {
  if (!pdr) {
    Logger::upf_app().error("GetUplinkTeidFromPdr: null PDR pointer");
    return 0;
  }

  pfcp::pdi pdi;
  if (!pdr->get(pdi)) {
    Logger::upf_app().debug(
        "GetUplinkTeidFromPdr: PDR %u has no PDI", pdr->pdr_id.rule_id);
    return 0;
  }

  // Check if this is an uplink PDR (source interface = ACCESS)
  pfcp::source_interface_t si;
  if (!pdi.get(si)) {
    Logger::upf_app().debug(
        "GetUplinkTeidFromPdr: PDR %u has no source interface",
        pdr->pdr_id.rule_id);
    return 0;
  }

  if (si.interface_value != pfcp::INTERFACE_VALUE_ACCESS) {
    // This is not an uplink PDR, return 0
    return 0;
  }

  // Get F-TEID from PDI (local F-TEID that UPF listens on)
  pfcp::fteid_t fteid;
  if (pdi.get(fteid)) {
    return fteid.teid;
  }

  Logger::upf_app().warn(
      "GetUplinkTeidFromPdr: PDR %u is uplink but has no F-TEID",
      pdr->pdr_id.rule_id);
  return 0;
}

//------------------------------------------------------------------------------
// Extract downlink TEID directly from FAR.
// Retrieves the remote F-TEID (Outer Header Creation) for sending GTP-U to gNB.
// §8.2.74 = FAR ID — TODO: verify correct §-ref for Outer Header Creation IE.
//------------------------------------------------------------------------------
uint32_t SessionManager::GetDownlinkTeidFromFar(
    std::shared_ptr<pfcp::pfcp_far> far) {
  if (!far) {
    Logger::upf_app().error("GetDownlinkTeidFromFar: null FAR pointer");
    return 0;
  }

  pfcp::forwarding_parameters fwd_params;
  if (!far->get(fwd_params)) {
    Logger::upf_app().debug(
        "GetDownlinkTeidFromFar: FAR %u has no forwarding parameters",
        far->far_id.far_id);
    return 0;
  }

  // Check destination interface (should be ACCESS for downlink)
  pfcp::destination_interface_t di;
  if (!fwd_params.get(di)) {
    Logger::upf_app().debug(
        "GetDownlinkTeidFromFar: FAR %u has no destination interface",
        far->far_id.far_id);
    return 0;
  }

  if (di.interface_value != pfcp::INTERFACE_VALUE_ACCESS) {
    // This is not a downlink FAR, return 0
    return 0;
  }

  // Get outer header creation TEID (remote F-TEID to send to gNB)
  if (fwd_params.outer_header_creation.first) {
    uint32_t teid = fwd_params.outer_header_creation.second.teid;
    // Logger::upf_app().debug(
    //     "GetDownlinkTeidFromFar: FAR %u has downlink TEID " TEID_FMT
    //     " (for gNB)",
    //     far->far_id.far_id, teid);
    return teid;
  }

  Logger::upf_app().debug(
      "GetDownlinkTeidFromFar: FAR %u is downlink but has no outer header "
      "creation",
      far->far_id.far_id);
  return 0;
}

//------------------------------------------------------------------------------
// const std::vector<std::shared_ptr<pfcp::pfcp_session>>&
// SessionManager::GetSessions() const {
//   // Note: Returning const reference to internal vector
//   // No mutex needed for const access to the vector itself
//   // (mutations to vector are protected by mutex in other methods)
//   return sessions_;
// }

//------------------------------------------------------------------------------
// Internal Methods - Categorize and Sort PDRs
// §8.2.11 Precedence — sort key for PDR ordering (Table 7.5.2.2-1)
//------------------------------------------------------------------------------

void SessionManager::CategorizePdrs(
    std::shared_ptr<pfcp::pfcp_session> session) {
  // Clear categorized lists first to avoid accumulating duplicates
  // on repeated calls (e.g. after each modification)
  session->pdrs_uplink.clear();
  session->pdrs_downlink.clear();
  session->qers_uplink.clear();
  session->qers_downlink.clear();

  for (auto& pdr : session->pdrs) {
    pfcp::pdi pdi;
    pfcp::source_interface_t source_interface;

    if (!(pdr->get(pdi) && pdi.get(source_interface))) {
      Logger::upf_app().warn(
          "PDR %u missing mandatory IE", pdr->pdr_id.rule_id);
      continue;
    }

    std::shared_ptr<pfcp::pfcp_qer> qer;
    bool has_qer = GetQerForPdr(session, pdr, qer);

    // §8.2.2 — Source Interface (§8.2.62 is UE IP Address — distinct IE)
    switch (source_interface.interface_value) {
      case pfcp::INTERFACE_VALUE_ACCESS: {
        session->pdrs_uplink.push_back(pdr);
        if (has_qer) {
          session->qers_uplink.push_back(qer);
        }
        break;
      }
      case pfcp::INTERFACE_VALUE_CORE: {
        session->pdrs_downlink.push_back(pdr);
        if (has_qer) {
          session->qers_downlink.push_back(qer);
        }
        break;
      }
      case INTERFACE_VALUE_SGI_LAN_N6_LAN:
      case INTERFACE_VALUE_CP_FUNCTION:
      case INTERFACE_VALUE_LI_FUNCTION:
        Logger::upf_n4().info(
            "Unhandled source interface for PDR: " +
            std::to_string(pdr->pdr_id.rule_id));
        break;

      default:
        Logger::upf_n4().warn(
            "Unknown source interface value: " +
            std::to_string(source_interface.interface_value));
        break;
    }
  }
}

//------------------------------------------------------------------------------
void SessionManager::SortPdrs(
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs) {
  std::sort(pdrs.begin(), pdrs.end(), ComparePdrPrecedence);
}

//------------------------------------------------------------------------------
bool SessionManager::ComparePdrPrecedence(
    const std::shared_ptr<pfcp::pfcp_pdr>& first,
    const std::shared_ptr<pfcp::pfcp_pdr>& second) {
  pfcp::precedence_t prec1, prec2;
  first->get(prec1);
  second->get(prec2);
  return prec1.precedence < prec2.precedence;  // Lower value = higher priority
}

//------------------------------------------------------------------------------
// Internal Removal Handlers
//------------------------------------------------------------------------------

size_t SessionManager::HandlePdrRemoval(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t removed_count = 0;

  for (const auto& remove_pdr : mod_req->pfcp_ies.remove_pdrs) {
    pfcp::pdr_id_t pdr_id;
    if (remove_pdr.get(pdr_id)) {
      if (RemovePdr(session->get_up_seid(), pdr_id.rule_id)) {
        removed_count++;
      }
    }
  }

  return removed_count;
}

//------------------------------------------------------------------------------
size_t SessionManager::HandleFarRemoval(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t removed_count = 0;

  for (const auto& remove_far : mod_req->pfcp_ies.remove_fars) {
    pfcp::far_id_t far_id;
    if (remove_far.get(far_id)) {
      if (RemoveFar(session->get_up_seid(), far_id.far_id)) {
        removed_count++;
      }
    }
  }

  return removed_count;
}

//------------------------------------------------------------------------------
size_t SessionManager::HandleQerRemoval(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t removed_count = 0;

  for (const auto& remove_qer : mod_req->pfcp_ies.remove_qers) {
    pfcp::qer_id_t qer_id;
    if (remove_qer.get(qer_id)) {
      if (RemoveQer(session->get_up_seid(), qer_id.qer_id)) {
        removed_count++;
      }
    }
  }

  return removed_count;
}

//------------------------------------------------------------------------------
size_t SessionManager::HandlePdrUpdates(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t updated_count = 0;

  for (const auto& update_pdr : mod_req->pfcp_ies.update_pdrs) {
    // Extract PDR ID — M, §8.2.36
    pfcp::pdr_id_t pdr_id_ie;
    if (!update_pdr.get(pdr_id_ie)) {
      Logger::upf_app().error("HandlePdrUpdates: PDR ID missing");
      continue;
    }
    uint16_t pdr_id = pdr_id_ie.rule_id;

    // Find existing PDR
    std::shared_ptr<pfcp::pfcp_pdr> existing_pdr = nullptr;
    for (auto& pdr : session->pdrs) {
      if (pdr && pdr->pdr_id.rule_id == pdr_id) {
        existing_pdr = pdr;
        break;
      }
    }

    if (!existing_pdr) {
      Logger::upf_app().error(
          "HandlePdrUpdates: PDR %u not found in session " SEID_FMT, pdr_id,
          session->get_up_seid());
      continue;
    }

    // -------------------------------------------------------------------------
    // Delegate standard field updates to pfcp_pdr::update() — Table 7.5.4.2-1.
    // This is the single source of truth for all IE-to-field assignments:
    //   §8.2.64  Outer Header Removal
    //   §8.2.11  Precedence
    //   PDI      grouped IE (source_interface, local_fteid, ue_ip_address,
    //            network_instance, sdf_filter, qfi — see PDI section below)
    //   §8.2.74  FAR ID
    //   §8.2.54  URR ID
    //   §8.2.75  QER ID
    //   (Activate Predefined Rules, Activation/Deactivation Time: TODO — see
    //    pfcp_pdr.cpp::update() for all in-progress TODOs)
    // -------------------------------------------------------------------------
    uint8_t cause_value = pfcp::CAUSE_VALUE_REQUEST_ACCEPTED;
    existing_pdr->update(update_pdr, cause_value);

    // -------------------------------------------------------------------------
    // MAR ID — C, §8.2.123, N4 only (Table 7.5.4.2-1)
    // pfcp_pdr::update() does not yet handle mar_id because pfcp::update_pdr
    // in the lib does not carry it (lib gap — msg_pfcp.hpp not updated to
    // V17.10.0). Wire manually when the lib is updated.
    // TODO: uncomment when lib update_pdr carries mar_id:
    //   pfcp::mar_id_t mar_id_ie;
    //   if (update_pdr.get(mar_id_ie)) {
    //     existing_pdr->mar_id.first  = true;
    //     existing_pdr->mar_id.second = mar_id_ie;
    //   }
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Activate Predefined Rules — C, §8.2.72, Sxb+Sxc+N4 (Table 7.5.4.2-1)
    // pfcp_pdr::update() has a TODO for this; provide the implementation here
    // so it is not silently lost on the SessionManager update path.
    // -------------------------------------------------------------------------
    if (update_pdr.has_activate_predefined_rules()) {
      const auto& activate_rules = update_pdr.get_activate_predefined_rules();
      for (const auto& rule : activate_rules) {
        Logger::upf_app().info(
            "PDR %u seid " SEID_FMT ": activate predefined rule '%s'", pdr_id,
            session->get_up_seid(), rule.predefined_rules_name.c_str());
        // TODO §8.2.72: predefined rule enforcement not yet implemented.
        // When implemented: look up rule in Configuration, apply policies,
        // update BPF map entries.
        existing_pdr->activate_predefined_rules.first  = true;
        existing_pdr->activate_predefined_rules.second = rule;
      }
    }

    // Deactivate Predefined Rules — C, §8.2.72, Sxb+Sxc+N4 (Table 7.5.4.2-1)
    if (update_pdr.has_deactivate_predefined_rules()) {
      const auto& deactivate_rules =
          update_pdr.get_deactivate_predefined_rules();
      for (const auto& rule : deactivate_rules) {
        Logger::upf_app().info(
            "PDR %u seid " SEID_FMT ": deactivate predefined rule '%s'", pdr_id,
            session->get_up_seid(), rule.predefined_rules_name.c_str());
        // TODO §8.2.72: deactivation not yet implemented.
        if (existing_pdr->activate_predefined_rules.first &&
            existing_pdr->activate_predefined_rules.second
                    .predefined_rules_name == rule.predefined_rules_name) {
          // Deactivate by clearing the field
          existing_pdr->activate_predefined_rules.first = false;
        }
      }
    }

    // -------------------------------------------------------------------------
    // PDI sub-IEs requiring dataplane interaction or not carried by lib
    // -------------------------------------------------------------------------
    pfcp::pdi pdi;
    if (update_pdr.get(pdi)) {
      // pfcp_pdr::update() stores the PDI wholesale via pdi.second assignment.
      // The following sub-IEs need additional handling beyond field storage.

      // Local F-TEID — §8.2.3, Sxa+Sxb+Sxc+N4
      // If CH=1 the CP asks the UPF to choose (allocate) a new TEID.
      // If CH=0 the CP supplies the TEID directly.
      // Both cases are already stored in existing_pdr->pdi.second.local_fteid
      // by pfcp_pdr::update() above. Handle CH here to ensure dataplane state
      // matches.
      pfcp::fteid_t new_fteid;
      if (pdi.get(new_fteid)) {
        if (new_fteid.ch) {
          // CH=1: allocate a new N3 TEID on behalf of the CP (§8.2.3).
          // TODO §8.2.3 CH/CHID: CHID (choose_id) selects from a TEID pool;
          //   not yet supported — allocate without pool selection for now.
          pfcp::fteid_t allocated_fteid = pfcp_switch_inst->generate_fteid_n3();
          // session->dataplane_->generate_fteid_n3();

          existing_pdr->pdi.second.local_fteid.first  = true;
          existing_pdr->pdi.second.local_fteid.second = allocated_fteid;
          Logger::upf_app().info(
              "PDR %u seid " SEID_FMT
              ": CH=1 in Update PDR F-TEID — allocated new TEID 0x%08x",
              pdr_id, session->get_up_seid(), allocated_fteid.teid);
        }
        // CH=0: TEID already stored correctly by pfcp_pdr::update() above.
      }

      // UE IP Address — §8.2.62, Sxa+Sxb+Sxc+N4
      // Flags: v4/v6 (address version), sd (source=0/destination=1),
      //        choos (UPF shall choose the UE IP address).
      pfcp::ue_ip_address_t ue_ip;
      if (pdi.get(ue_ip)) {
        if (ue_ip.chv4 || ue_ip.chv6) {
          // CHV4/CHV6=1: CP requests UPF to allocate a UE IP address and report
          // it back (3GPP TS 29.244 §8.2.62, Rel-16). UE IP pool assignment is
          // not yet implemented.
          // TODO §8.2.62 CHV4/CHV6: allocate from UE IP pool, store result, and
          //   include it in the Session Establishment/Modification Response or
          //   trigger a Session Report Request with IPMA cause. For now log and
          //   continue.
          Logger::upf_app().warn(
              "PDR %u seid " SEID_FMT
              ": CHOOS=1 in Update PDR UE IP Address — UE IP"
              " pool allocation not yet implemented",
              pdr_id, session->get_up_seid());
        } else {
          // v4/v6 flags indicate which address field is valid.
          if (ue_ip.v4) {
            char ip_str[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &ue_ip.ipv4_address, ip_str, INET_ADDRSTRLEN);
            Logger::upf_app().debug(
                "PDR %u seid " SEID_FMT ": Update PDR UE IP v4=%s sd=%u",
                pdr_id, session->get_up_seid(), ip_str, ue_ip.sd);
          }
          if (ue_ip.v6) {
            // IPv6 stored by pfcp_pdr::update(); log only for now.
            Logger::upf_app().debug(
                "PDR %u seid " SEID_FMT
                ": Update PDR UE IP has v6 address (sd=%u)",
                pdr_id, session->get_up_seid(), ue_ip.sd);
          }
        }
      }

      // QFI — §8.2.89, N4+N4mb (PDI sub-IE, Table 7.5.2.2-1 / 7.5.4.2-1)
      // pfcp_pdr::update() stores the whole PDI including qfi; explicit log.
      pfcp::qfi_t qfi_ie;
      if (pdi.get(qfi_ie)) {
        Logger::upf_app().debug(
            "PDR %u seid " SEID_FMT ": Update PDR QFI=%u", pdr_id,
            session->get_up_seid(), qfi_ie.qfi);
        // Value already stored via pfcp_pdr::update() → pdi whole-replace.
      }
    }

    updated_count++;
  }  // end for (update_pdr)

  // Re-categorize and update BPF maps once for all updated PDRs
  if (updated_count > 0) {
    CategorizePdrs(session);
    SortPdrs(session->pdrs_uplink);
    SortPdrs(session->pdrs_downlink);
    session_program_manager_->ModifyPipeline(session);
  }

  return updated_count;
}

//------------------------------------------------------------------------------
size_t SessionManager::HandleFarUpdates(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t updated_count = 0;

  for (const auto& update_far : mod_req->pfcp_ies.update_fars) {
    // Extract FAR ID — M, §8.2.74
    pfcp::far_id_t far_id_ie;
    if (!update_far.get(far_id_ie)) {
      Logger::upf_app().error("HandleFarUpdates: FAR ID missing");
      continue;
    }
    uint32_t far_id = far_id_ie.far_id;

    // Find existing FAR
    std::shared_ptr<pfcp::pfcp_far> existing_far = nullptr;
    for (auto& far : session->fars) {
      if (far && far->far_id.far_id == far_id) {
        existing_far = far;
        break;
      }
    }

    if (!existing_far) {
      Logger::upf_app().error(
          "HandleFarUpdates: FAR %u not found in session " SEID_FMT, far_id,
          session->get_up_seid());
      continue;
    }

    // -------------------------------------------------------------------------
    // Delegate to pfcp_far::update() — Table 7.5.4.3-1 single source of truth:
    //   §8.2.26  Apply Action (C)
    //   grouped  Update Forwarding Parameters (Table 7.5.4.3-2):
    //              destination_interface, network_instance, OHC, TLM,
    //              forwarding_policy, header_enrichment, pfcpsmreq_flags
    //   grouped  Update Duplicating Parameters (Table 7.5.4.3-3):
    //              destination_interface, OHC, TLM, forwarding_policy
    //   §8.2.57  BAR ID (C)
    //   TODOs inside pfcp_far::update():
    //     grouped=270 Redundant Transmission Forwarding Parameters (C, N4)
    //     grouped=302 Add MBS Unicast Parameters (C, N4mb)
    //     grouped=303 Remove MBS Unicast Parameters (C, N4mb)
    //     §8.2.31 PFCPSMReq-Flags SNDEM/DROBU/QAURR not acted on
    // -------------------------------------------------------------------------
    uint8_t cause_value = pfcp::CAUSE_VALUE_REQUEST_ACCEPTED;
    existing_far->update(update_far, cause_value);

    // Log OHC IPv4/IPv6 changes for diagnostics
    if (update_far.update_forwarding_parameters.first) {
      const auto& fp = update_far.update_forwarding_parameters.second;
      if (fp.outer_header_creation.first) {
        const auto& ohc            = fp.outer_header_creation.second;
        char ip4[INET_ADDRSTRLEN]  = {};
        char ip6[INET6_ADDRSTRLEN] = {};
        if (ohc.outer_header_creation_description &
            pfcp::OUTER_HEADER_CREATION_GTPU_UDP_IPV4) {
          inet_ntop(AF_INET, &ohc.ipv4_address, ip4, INET_ADDRSTRLEN);
          Logger::upf_app().debug(
              "FAR %u seid " SEID_FMT
              ": Update OHC — TEID=0x%08x gNB_v4=%s port=%u",
              far_id, session->get_up_seid(), ohc.teid, ip4, ohc.port_number);
        }
        if (ohc.outer_header_creation_description &
            pfcp::OUTER_HEADER_CREATION_GTPU_UDP_IPV6) {
          inet_ntop(AF_INET6, &ohc.ipv6_address, ip6, INET6_ADDRSTRLEN);
          Logger::upf_app().debug(
              "FAR %u seid " SEID_FMT
              ": Update OHC — TEID=0x%08x gNB_v6=%s port=%u",
              far_id, session->get_up_seid(), ohc.teid, ip6, ohc.port_number);
        }
      }
      /*
            pfcp::network_instance_t network_instance;
            if (update_fp.get(network_instance)) {
              existing_far->forwarding_parameters.second.network_instance.first
         = true;
              existing_far->forwarding_parameters.second.network_instance.second
         = network_instance;
            }

            pfcp::outer_header_creation_t ohc;
            if (update_fp.get(ohc)) {
              existing_far->forwarding_parameters.second.outer_header_creation.first
         = true;
              existing_far->forwarding_parameters.second.outer_header_creation
                  .second = ohc;
            }

            pfcp::transport_level_marking_t tlm;
            if (update_fp.get(tlm)) {
              existing_far->forwarding_parameters.second.transport_level_marking
                  .first = true;
              existing_far->forwarding_parameters.second.transport_level_marking
                  .second = tlm;
            }

            pfcp::forwarding_policy_t fwd_policy;
            if (update_fp.get(fwd_policy)) {
              existing_far->forwarding_parameters.second.forwarding_policy.first
         = true;
              existing_far->forwarding_parameters.second.forwarding_policy.second
         = fwd_policy;
            }

            pfcp::header_enrichment_t header_enrich;
            if (update_fp.get(header_enrich)) {
              existing_far->forwarding_parameters.second.header_enrichment.first
         = true;
              existing_far->forwarding_parameters.second.header_enrichment.second
         = header_enrich;
            }
          }

          pfcp::update_duplicating_parameters update_dp;
          if (update_far.get(update_dp)) {
            existing_far->duplicating_parameters.first = true;

            pfcp::destination_interface_t dest_if;
            if (update_dp.get(dest_if)) {
              existing_far->duplicating_parameters.second.destination_interface
                  .first = true;
              existing_far->duplicating_parameters.second.destination_interface
                  .second = dest_if;
            }

            pfcp::outer_header_creation_t ohc;
            if (update_dp.get(ohc)) {
              existing_far->duplicating_parameters.second.outer_header_creation
                  .first = true;
              existing_far->duplicating_parameters.second.outer_header_creation
                  .second = ohc;
            }

            pfcp::transport_level_marking_t tlm;
            if (update_dp.get(tlm)) {
              existing_far->duplicating_parameters.second.transport_level_marking
                  .first = true;
              existing_far->duplicating_parameters.second.transport_level_marking
                  .second = tlm;
            }

            pfcp::forwarding_policy_t fp;
            if (update_dp.get(fp)) {
              existing_far->duplicating_parameters.second.forwarding_policy.first
         = true;
              existing_far->duplicating_parameters.second.forwarding_policy.second
         = fp;
            }
          }

          pfcp::bar_id_t bar_id;
          if (update_far.get(bar_id)) {
            existing_far->bar_id.first  = true;
            existing_far->bar_id.second = bar_id;
      */
    }

    updated_count++;
  }

  // Update BPF maps
  if (updated_count > 0) {
    session_program_manager_->ModifyPipeline(session);
  }

  return updated_count;
}

//------------------------------------------------------------------------------
size_t SessionManager::HandleQerUpdates(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t updated_count = 0;

  for (const auto& update_qer : mod_req->pfcp_ies.update_qers) {
    // Extract QER ID — M, §8.2.75
    pfcp::qer_id_t qer_id_ie;
    if (!update_qer.get(qer_id_ie)) {
      Logger::upf_app().error("HandleQerUpdates: QER ID missing");
      continue;
    }
    uint32_t qer_id = qer_id_ie.qer_id;

    // Find existing QER
    std::shared_ptr<pfcp::pfcp_qer> existing_qer = nullptr;
    for (auto& qer : session->qers) {
      if (qer && qer->qer_id.second.qer_id == qer_id) {
        existing_qer = qer;
        break;
      }
    }

    if (!existing_qer) {
      Logger::upf_app().error(
          "HandleQerUpdates: QER %u not found in session " SEID_FMT, qer_id,
          session->get_up_seid());
      continue;
    }

    // -------------------------------------------------------------------------
    // Delegate to pfcp_qer::update() — Table 7.5.4.5-1 single source of truth:
    //   §8.2.75  QER ID
    //   §8.2.10  QER Correlation ID (O)
    //   §8.2.7   Gate Status (C)
    //   §8.2.8   MBR (C)
    //   §8.2.9   GBR (C)
    //   §8.2.89  QFI (C)
    //   §8.2.88  RQI — Reflective QoS Indication (C)
    //   §8.2.116 Paging Policy Indicator (O)
    //   §8.2.115 Averaging Window (O)
    //   TODOs inside pfcp_qer::update():
    //     §8.2.63  Packet Rate (C, Sxb+N4) — excluded, no enforcement path
    //     §8.2.66  DL Flow Level Marking (C, Sxb+Sxc) — excluded, N4 n/a
    //     §8.2.174 QER Control Indications (C, Sxb+N4) — lib gap
    //     §8.2.216 QER Indications (C, N4mb) — not in lib
    // -------------------------------------------------------------------------
    uint8_t cause_value = pfcp::CAUSE_VALUE_REQUEST_ACCEPTED;
    existing_qer->update(update_qer, cause_value);

    updated_count++;
  }

  // Re-categorize and update BPF maps
  if (updated_count > 0) {
    CategorizePdrs(session);
    session_program_manager_->ModifyPipeline(session);
  }

  return updated_count;
}

//==============================================================================
// URR Management — §7.5.2.4 Create URR / §7.5.4.4 Update URR / §7.5.4.8 Remove
// URR
//==============================================================================

// §7.5.2.4 Create URR — Table 7.5.2.4-1
bool SessionManager::AddUrr(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_urr> urr) {
  if (!urr) {
    Logger::upf_app().error("AddUrr: null URR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error("AddUrr: session " SEID_FMT " not found", seid);
      return false;
    }

    session->urrs.push_back(urr);
    session_program_manager_->CreatePipeline(session);

    Logger::upf_app().info(
        "Added URR %u to session " SEID_FMT, urr->urr_id.second.urr_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("AddUrr failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.4 Update URR — Table 7.5.4.4-1
bool SessionManager::UpdateUrr(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_urr> urr) {
  if (!urr) {
    Logger::upf_app().error("UpdateUrr: null URR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "UpdateUrr: session " SEID_FMT " not found", seid);
      return false;
    }

    uint32_t urr_id = urr->urr_id.second.urr_id;
    bool found      = false;

    for (auto& existing : session->urrs) {
      if (existing->urr_id.second.urr_id == urr_id) {
        existing = urr;
        found    = true;
        break;
      }
    }

    if (!found) {
      Logger::upf_app().error(
          "UpdateUrr: URR %u not found in session " SEID_FMT, urr_id, seid);
      return false;
    }

    // ModifyPipeline repopulates urr_config_map (BPF_ANY) while preserving
    // urr_volume_counters_map counters (BPF_NOEXIST in PopulateUrrConfigMap)
    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info("Updated URR %u in session " SEID_FMT, urr_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("UpdateUrr failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.8 Remove URR — Table 7.5.4.8-1
bool SessionManager::RemoveUrr(uint64_t seid, uint32_t urr_id) {
  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "RemoveUrr: session " SEID_FMT " not found", seid);
      return false;
    }

    session->urrs.erase(
        std::remove_if(
            session->urrs.begin(), session->urrs.end(),
            [urr_id](const auto& u) {
              return u->urr_id.second.urr_id == urr_id;
            }),
        session->urrs.end());

    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info(
        "Removed URR %u from session " SEID_FMT, urr_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("RemoveUrr failed: %s", e.what());
    return false;
  }
}

//==============================================================================
// BAR Management — §7.5.2.6 Create BAR / §7.5.4.6 Update BAR / §7.5.4.10 Remove
// BAR
//==============================================================================

// §7.5.2.6 Create BAR — Table 7.5.2.6-1
bool SessionManager::AddBar(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_bar> bar) {
  if (!bar) {
    Logger::upf_app().error("AddBar: null BAR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error("AddBar: session " SEID_FMT " not found", seid);
      return false;
    }

    session->bars.push_back(bar);
    session_program_manager_->CreatePipeline(session);

    Logger::upf_app().info(
        "Added BAR %u to session " SEID_FMT, bar->bar_id.second.bar_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("AddBar failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.6 Update BAR — Table 7.5.4.6-1
bool SessionManager::UpdateBar(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_bar> bar) {
  if (!bar) {
    Logger::upf_app().error("UpdateBar: null BAR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "UpdateBar: session " SEID_FMT " not found", seid);
      return false;
    }

    uint32_t bar_id = bar->bar_id.second.bar_id;
    bool found      = false;

    for (auto& existing : session->bars) {
      if (existing->bar_id.second.bar_id == bar_id) {
        existing = bar;
        found    = true;
        break;
      }
    }

    if (!found) {
      Logger::upf_app().error(
          "UpdateBar: BAR %u not found in session " SEID_FMT, bar_id, seid);
      return false;
    }

    // ModifyPipeline repopulates bar_config_map while preserving
    // bar_state_map (DDN tracking state, BPF_NOEXIST in PopulateBarConfigMap)
    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info("Updated BAR %u in session " SEID_FMT, bar_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("UpdateBar failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.10 Remove BAR — Table 7.5.4.10-1
bool SessionManager::RemoveBar(uint64_t seid, uint32_t bar_id) {
  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "RemoveBar: session " SEID_FMT " not found", seid);
      return false;
    }

    session->bars.erase(
        std::remove_if(
            session->bars.begin(), session->bars.end(),
            [bar_id](const auto& b) {
              return b->bar_id.second.bar_id == bar_id;
            }),
        session->bars.end());

    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info(
        "Removed BAR %u from session " SEID_FMT, bar_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("RemoveBar failed: %s", e.what());
    return false;
  }
}

//==============================================================================
// MAR Management — §7.5.2.8 Create MAR / §7.5.4.16 Update MAR / §7.5.4.15
// Remove MAR
//                  3GPP TS 23.501 §5.32 — ATSSS
//==============================================================================

// §7.5.2.8 Create MAR — Table 7.5.2.8-1
bool SessionManager::AddMar(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_mar> mar) {
  if (!mar) {
    Logger::upf_app().error("AddMar: null MAR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error("AddMar: session " SEID_FMT " not found", seid);
      return false;
    }

    session->mars.push_back(mar);
    session_program_manager_->CreatePipeline(session);

    Logger::upf_app().info(
        "Added MAR %u to session " SEID_FMT, mar->mar_id.second.mar_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("AddMar failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.16 Update MAR — Table 7.5.4.16-1
bool SessionManager::UpdateMar(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_mar> mar) {
  if (!mar) {
    Logger::upf_app().error("UpdateMar: null MAR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "UpdateMar: session " SEID_FMT " not found", seid);
      return false;
    }

    uint32_t mar_id = mar->mar_id.second.mar_id;
    bool found      = false;

    for (auto& existing : session->mars) {
      if (existing->mar_id.second.mar_id == mar_id) {
        existing = mar;
        found    = true;
        break;
      }
    }

    if (!found) {
      Logger::upf_app().error(
          "UpdateMar: MAR %u not found in session " SEID_FMT, mar_id, seid);
      return false;
    }

    // ModifyPipeline repopulates mar_rules_map in BPF
    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info("Updated MAR %u in session " SEID_FMT, mar_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("UpdateMar failed: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
// §7.5.4.15 Remove MAR — Table 7.5.4.15-1
bool SessionManager::RemoveMar(uint64_t seid, uint32_t mar_id) {
  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto session = GetSessionUnlocked(seid);
    if (!session) {
      Logger::upf_app().error(
          "RemoveMar: session " SEID_FMT " not found", seid);
      return false;
    }

    session->mars.erase(
        std::remove_if(
            session->mars.begin(), session->mars.end(),
            [mar_id](const auto& m) {
              return m->mar_id.second.mar_id == mar_id;
            }),
        session->mars.end());

    session_program_manager_->ModifyPipeline(session);

    Logger::upf_app().info(
        "Removed MAR %u from session " SEID_FMT, mar_id, seid);
    return true;

  } catch (const std::exception& e) {
    Logger::upf_app().error("RemoveMar failed: %s", e.what());
    return false;
  }
}

//==============================================================================
// Internal N4 Modification Handlers — URR/BAR/MAR
// Reference: 3GPP TS 29.244 V17.10.0 §7.5.4 — PFCP Session Modification Request
//==============================================================================

//------------------------------------------------------------------------------
// §7.5.4.8 Remove URR — Table 7.5.4.8-1
size_t SessionManager::HandleUrrRemoval(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t removed_count = 0;

  for (const auto& remove_urr : mod_req->pfcp_ies.remove_urrs) {
    pfcp::urr_id_t urr_id;
    if (remove_urr.get(urr_id)) {
      if (RemoveUrr(session->get_up_seid(), urr_id.urr_id)) {
        removed_count++;
      }
    }
  }

  return removed_count;
}

//------------------------------------------------------------------------------
// §7.5.4.10 Remove BAR — Table 7.5.4.10-1
size_t SessionManager::HandleBarRemoval(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t removed_count = 0;

  for (const auto& remove_bar : mod_req->pfcp_ies.remove_bars) {
    pfcp::bar_id_t bar_id;
    if (remove_bar.get(bar_id)) {
      if (RemoveBar(session->get_up_seid(), bar_id.bar_id)) {
        removed_count++;
      }
    }
  }

  return removed_count;
}

//------------------------------------------------------------------------------
// §7.5.4.15 Remove MAR — Table 7.5.4.15-1
size_t SessionManager::HandleMarRemoval(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t removed_count = 0;

  for (const auto& remove_mar : mod_req->pfcp_ies.remove_mars) {
    pfcp::mar_id_t mar_id;
    if (remove_mar.get(mar_id)) {
      if (RemoveMar(session->get_up_seid(), mar_id.mar_id)) {
        removed_count++;
      }
    }
  }

  return removed_count;
}

//------------------------------------------------------------------------------
// §7.5.4.4 Update URR — Table 7.5.4.4-1
// Applies updated reporting triggers, thresholds, quotas, and timing fields.
// Volume counters in urr_volume_counters_map are preserved (BPF_NOEXIST write).
size_t SessionManager::HandleUrrUpdates(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t updated_count = 0;

  for (const auto& update_urr : mod_req->pfcp_ies.update_urrs) {
    // URR ID — M, §8.2.54
    pfcp::urr_id_t urr_id_ie;
    if (!update_urr.get(urr_id_ie)) {
      Logger::upf_app().error("HandleUrrUpdates: URR ID missing");
      continue;
    }
    uint32_t urr_id = urr_id_ie.urr_id;

    // Find existing URR in session
    std::shared_ptr<pfcp::pfcp_urr> existing = nullptr;
    for (auto& u : session->urrs) {
      if (u && u->urr_id.second.urr_id == urr_id) {
        existing = u;
        break;
      }
    }

    if (!existing) {
      Logger::upf_app().error(
          "HandleUrrUpdates: URR %u not found in session " SEID_FMT, urr_id,
          session->get_up_seid());
      continue;
    }

    // -------------------------------------------------------------------------
    // Delegate to pfcp_urr::update() — Table 7.5.4.4-1 single source of truth.
    // All 20+ optional/conditional IEs from Table 7.5.4.4-1 are applied there:
    //   §8.2.40  Measurement Method
    //   §8.2.19  Reporting Triggers
    //   §8.2.42  Measurement Period
    //   §8.2.13  Volume Threshold
    //   §8.2.50  Volume Quota
    //   §8.2.14  Time Threshold
    //   §8.2.51  Time Quota
    //   §8.2.48  Quota Holding Time
    //   §8.2.49  Dropped DL Traffic Threshold
    //   §8.2.15  Monitoring Time
    //   §8.2.16  Subsequent Volume Threshold
    //   §8.2.17  Subsequent Time Threshold
    //   §8.2.86  Subsequent Volume Quota
    //   §8.2.87  Subsequent Time Quota
    //   §8.2.18  Inactivity Detection Time
    //   §8.2.55  Linked URR ID
    //   §8.2.68  Measurement Information
    //   §8.2.81  Time Quota Mechanism (Sxb only)
    //   IE 118   Aggregated URRs (Sxb only)
    //   §8.2.74  FAR ID for Quota Action
    //   §8.2.105 Ethernet Inactivity Timer (N4)
    //   IE 147   Additional Monitoring Time
    //   grouped  Event Information (event_id + event_threshold)
    //   TODOs inside pfcp_urr::update():
    //     §8.2.107 Subsequent Event Threshold (lib gap)
    //     §8.2.106 Subsequent Event Quota (lib gap)
    //     §8.2.133 Number of Reports (lib gap)
    //     §8.2.83  User Plane Inactivity Timer (lib gap)
    //     §8.2.78  Exempted App ID for Quota Action (lib gap)
    //     §8.2.5   Exempted SDF Filter for Quota Action (lib gap)
    // -------------------------------------------------------------------------
    uint8_t cause_value = pfcp::CAUSE_VALUE_REQUEST_ACCEPTED;
    existing->update(update_urr, cause_value);

    updated_count++;
  }

  // Update BPF urr_config_map (volume counters preserved via BPF_NOEXIST)
  if (updated_count > 0) {
    session_program_manager_->ModifyPipeline(session);
  }

  return updated_count;
}

//------------------------------------------------------------------------------
// §7.5.4.6 Update BAR — Table 7.5.4.6-1 (Table 7.5.4.11-1)
// Applies updated DDN delay and buffering packet count hint.
// Runtime bar_state_map (DDN tracking, pkt count) is preserved.
size_t SessionManager::HandleBarUpdates(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t updated_count = 0;

  for (const auto& update_bar : mod_req->pfcp_ies.update_bars) {
    // BAR ID — M, §8.2.57
    pfcp::bar_id_t bar_id_ie;
    if (!update_bar.get(bar_id_ie)) {
      Logger::upf_app().error("HandleBarUpdates: BAR ID missing");
      continue;
    }
    uint32_t bar_id = bar_id_ie.bar_id;

    // Find existing BAR in session
    std::shared_ptr<pfcp::pfcp_bar> existing = nullptr;
    for (auto& b : session->bars) {
      if (b && b->bar_id.second.bar_id == bar_id) {
        existing = b;
        break;
      }
    }

    if (!existing) {
      Logger::upf_app().error(
          "HandleBarUpdates: BAR %u not found in session " SEID_FMT, bar_id,
          session->get_up_seid());
      continue;
    }

    // -------------------------------------------------------------------------
    // Delegate to pfcp_bar::update(modification_request) — Table 7.5.4.11-1.
    // This is the single source of truth for the BAR Session Modification path:
    //   §8.2.28  Downlink Data Notification Delay (Sxa + N4)
    //   §8.2.100 Suggested Buffering Packets Count (Sxb+Sxc+N4, UDBC feature)
    //   TODOs inside pfcp_bar::update(modification_request):
    //     §8.2.29 DL Buffering Duration (Sxa+N4) — lib gap,
    //             not in update_bar_within_pfcp_session_modification_request
    //     §8.2.30 DL Buffering Suggested Packet Count (Sxa+N4) — same lib gap
    // -------------------------------------------------------------------------
    uint8_t cause_value = pfcp::CAUSE_VALUE_REQUEST_ACCEPTED;
    existing->update(update_bar, cause_value);

    updated_count++;
  }

  // Update BPF bar_config_map (bar_state_map preserved via BPF_NOEXIST)
  if (updated_count > 0) {
    session_program_manager_->ModifyPipeline(session);
  }

  return updated_count;
}

//------------------------------------------------------------------------------
// §7.5.4.16 Update MAR — Table 7.5.4.16-1
// Applies updated steering functionality, steering mode, Access Forwarding
// Action Info (AFAI) for 3GPP and non-3GPP access paths, Threshold Values,
// and Steering Mode Indicator.
size_t SessionManager::HandleMarUpdates(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t updated_count = 0;

  for (const auto& update_mar : mod_req->pfcp_ies.update_mars) {
    // MAR ID — M, §8.2.123
    pfcp::mar_id_t mar_id_ie;
    if (!update_mar.get(mar_id_ie)) {
      Logger::upf_app().error("HandleMarUpdates: MAR ID missing");
      continue;
    }
    uint32_t mar_id = mar_id_ie.mar_id;

    // Find existing MAR in session
    std::shared_ptr<pfcp::pfcp_mar> existing = nullptr;
    for (auto& m : session->mars) {
      if (m && m->mar_id.second.mar_id == mar_id) {
        existing = m;
        break;
      }
    }

    if (!existing) {
      Logger::upf_app().error(
          "HandleMarUpdates: MAR %u not found in session " SEID_FMT, mar_id,
          session->get_up_seid());
      continue;
    }

    // =========================================================================
    // Table 7.5.4.16-1 — Update MAR IEs (all N4-only)
    // =========================================================================

    // Steering Functionality — M, §8.2.124 (IE type 171)
    // Values: ATSSS-LL (0), MPTCP (1)
    pfcp::steering_functionality_t steer_func;
    if (update_mar.steering_functionality.first) {
      existing->steering_functionality.first  = true;
      existing->steering_functionality.second = steer_func;
    }

    // Steering Mode — M, §8.2.125 (IE type 172)
    // Values: Active-Standby (0), Smallest Delay (1), Load Balancing (2),
    //         Priority-based (3)
    pfcp::steering_mode_t steer_mode;
    if (update_mar.get(steer_mode)) {
      existing->steering_mode.first  = true;
      existing->steering_mode.second = steer_mode;
    }

    // AFAI conversion lambda — reused for both 3GPP and non-3GPP paths.
    // Matches the conversion in pfcp_session::update(mar) (pfcp_session.cpp).
    // TODO V17.10.0: Update 3GPP/Non-3GPP AFAI (Tables 7.5.4.16-2/3) not
    // yet in lib's update_mar type — handled as full replace for now.
    auto convert_afai =
        [](const pfcp::access_forwarding_action_information& afai,
           std::pair<bool, pfcp::mar_access_forwarding_action_t>& dst_pair) {
          pfcp::mar_access_forwarding_action_t dst{};

          // FAR ID — M in AFAI, §8.2.74
          pfcp::far_id_t far_val;
          if (afai.get(far_val)) dst.far_id = far_val;

          // URR ID — C, per-access usage reporting (§8.2.54)
          pfcp::urr_id_t urr_val;
          if (afai.get(urr_val)) {
            dst.urr_id         = urr_val;
            dst.urr_id_present = true;
          }

          // Weight — C, Load Balancing mode (§8.2.126)
          if (afai.weight.first) {
            dst.weight.weight_value = afai.weight.second;
            dst.weight_present      = true;
          }

          // Priority — C, Active-Standby / Priority-based mode (§8.2.127)
          if (afai.priority.first) {
            dst.priority.priority_value = afai.priority.second;
            dst.priority_present        = true;
          }

          // TODO §8.2.186 — RAT Type (O, N4, Tables 7.5.4.16-2/3)
          //   Not yet in pfcp::access_forwarding_action_information (lib gap).
          //   Add when lib is updated.

          dst_pair = {true, dst};
        };

    // 3GPP Access Forwarding Action Info — C, §IE type 166
    // Table 7.5.4.16-2 sub-IEs: FAR ID, Weight, Priority, URR ID, RAT Type
    pfcp::access_forwarding_action_information afai_3gpp;
    if (update_mar.get_access_forwarding_action_information_1(afai_3gpp)) {
      convert_afai(afai_3gpp, existing->access_forwarding_action_info_1);
    }

    // Non-3GPP Access Forwarding Action Info — C, §IE type 167
    // Table 7.5.4.16-3 sub-IEs: FAR ID, Weight, Priority, URR ID, RAT Type
    pfcp::access_forwarding_action_information afai_non3gpp;
    if (update_mar.get_access_forwarding_action_information_2(afai_non3gpp)) {
      convert_afai(afai_non3gpp, existing->access_forwarding_action_info_2);
    }

    // TODO: Update 3GPP Access Fwd Action (IE type 175, Table 7.5.4.16-1)
    //   and Update Non-3GPP Access Fwd Action (IE type 176, Table 7.5.4.16-1)
    //   — distinct from Create AFAI types above; not yet in lib update_mar.

    updated_count++;
  }

  // Update BPF mar_rules_map
  if (updated_count > 0) {
    session_program_manager_->ModifyPipeline(session);
  }

  return updated_count;
}
