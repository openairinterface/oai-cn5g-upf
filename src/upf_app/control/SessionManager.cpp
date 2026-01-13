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
 * according to 3GPP TS 29.244 specifications.
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
#include "itti_msg_n4.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

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
// Reference: 3GPP TS 29.244 Section 5.2
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
      "[N4] Create session: seid " SEID_FMT "- Validating session context",
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

    // Categorize and sort PDRs (3GPP TS 29.244 Section 8.2.29 - Precedence)
    CategorizePdrs(session);
    SortPdrs(session->pdrs_uplink);
    SortPdrs(session->pdrs_downlink);

    // Get TEIDs for pipeline update
    uint32_t teid_dl = RetrieveTeid(session);
    uint32_t teid_ul = FindUplinkTeid(seid);

    // Create BPF pipeline
    Logger::upf_app().debug(
        "[N4] Create Session: seid 0x%lx - Creating eBPF data-path pipeline [ "
        "teid_ul 0x%, teid_dl 0x% ]",
        seid, teid_ul, teid_dl);
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
// SessionOperationResult SessionManager::UpdateSession(
//     std::shared_ptr<pfcp::pfcp_session> session) {
//   if (!session) {
//     Logger::upf_app().info(
//         "[N4] Update Session: Invalid session pointer (null)");
//     return SessionOperationResult(false, "Invalid session pointer", 0);
//   }

//   uint64_t seid = session->get_up_seid();
//   Logger::upf_app().debug(
//       "[N4] Update Session: seid " SEID_FMT "- Validating session context",
//       seid);

//   try {
//     std::lock_guard<std::mutex> lock(sessions_mutex_);

//     auto it = seid_to_session_.find(seid);
//     if (it == seid_to_session_.end()) {
//       Logger::upf_app().error(
//           "[N4] Update Session: seid " SEID_FMT
//           "- Session not found in registry",
//           seid);
//       return SessionOperationResult(false, "Session not found", seid);
//     }

//     // Update session reference
//     it->second = session;

//     // Re-categorize and sort PDRs
//     CategorizePdrs(session);
//     SortPdrs(session->pdrs_uplink);
//     SortPdrs(session->pdrs_downlink);

//     // Get TEIDs for pipeline update
//     uint32_t teid_dl = RetrieveTeid(session);
//     uint32_t teid_ul = FindUplinkTeid(seid);

//     // Modify BPF pipeline
//     Logger::upf_app().debug(
//         "[N4] Update Session: seid 0x%lx - "
//         "Updating eBPF data-path pipeline [ teid_ul 0x%08x, teid_dl 0x%08x
//         ]", seid, teid_ul, teid_dl);
//     if (teid_dl > 0 || teid_ul > 0) {
//       session_program_manager_->ModifyPipeline(session, teid_ul, teid_dl);
//     }

//     Logger::upf_app().info(
//         "[N4] Update Session: seid 0x%lx - eBPF data-path Pipeline updated "
//         "successfully",
//         seid);
//     return SessionOperationResult(true, "Session updated", seid);

//   } catch (const std::exception& e) {
//     Logger::upf_app().error(
//         "[N4] Update Session: seid 0x%lx - Exception: %s", seid, e.what());
//     return SessionOperationResult(
//         false, std::string("Exception: ") + e.what(), seid);
//   }
// }

SessionOperationResult SessionManager::UpdateSession(
    std::shared_ptr<pfcp::pfcp_session> session) {
  Logger::upf_app().error("MOD_A: UpdateSession START");

  if (!session) {
    return SessionOperationResult(false, "Invalid session pointer", 0);
  }

  uint64_t seid = session->get_up_seid();
  Logger::upf_app().error("MOD_C: UpdateSession SEID=0x%lx", seid);

  try {
    auto it = seid_to_session_.find(seid);
    if (it == seid_to_session_.end()) {
      return SessionOperationResult(false, "Session not found", seid);
    }

    Logger::upf_app().error("MOD_F: Before session update");
    it->second = session;

    Logger::upf_app().error("MOD_G: Before CategorizePdrs");
    CategorizePdrs(session);

    Logger::upf_app().error("MOD_H: After CategorizePdrs");
    SortPdrs(session->pdrs_uplink);
    SortPdrs(session->pdrs_downlink);

    Logger::upf_app().error("MOD_J: Before RetrieveTeid");
    uint32_t teid_dl = RetrieveTeid(session);
    uint32_t teid_ul = FindUplinkTeid(seid);

    Logger::upf_app().error(
        "MOD_M: TEIDs: ul=0x%08x dl=0x%08x", teid_ul, teid_dl);

    if (teid_dl > 0 || teid_ul > 0) {
      Logger::upf_app().error("MOD_N: Before ModifyPipeline");

      session_program_manager_->ModifyPipeline(session, teid_ul, teid_dl);

      Logger::upf_app().error("MOD_O: After ModifyPipeline - SUCCESS");
    } else {
      Logger::upf_app().error("MOD_P: Skipped ModifyPipeline (no TEIDs)");
    }

    Logger::upf_app().error("MOD_Q: UpdateSession COMPLETE");
    return SessionOperationResult(true, "Session updated", seid);

  } catch (const std::exception& e) {
    Logger::upf_app().error("MOD_EXCEPTION: %s", e.what());
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

    // Get TEIDs for pipeline update
    uint32_t teid_dl = RetrieveTeid(it->second);
    uint32_t teid_ul = FindUplinkTeid(seid);

    // Remove from BPF pipeline
    Logger::upf_app().debug(
        "[N4] Delete Session: seid 0x%lx - "
        "Deleting eBPF data-path pipeline [ teid_ul 0x%08x, teid_dl 0x%08x ]",
        seid, teid_ul, teid_dl);
    session_program_manager_->RemovePipeline(seid);
    Logger::upf_app().info(
        "[N4] Delete Session: seid 0x%lx - eBPF data-path pipeline deleted "
        "successfully",
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

    return SessionOperationResult(true, "Session deleted", seid);

  } catch (const std::exception& e) {
    Logger::upf_app().error(
        "[N4] Delete Session: seid 0x%lx - Exception: %s", seid, e.what());
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
std::vector<std::shared_ptr<pfcp::pfcp_session>>
SessionManager::GetAllSessions() const {
  std::lock_guard<std::mutex> lock(sessions_mutex_);
  return sessions_;
}

//------------------------------------------------------------------------------
// N4 Message Handlers
// Reference: 3GPP TS 29.244 Section 6
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
// 3GPP TS 29.244 Section 7.5.4.2 - PFCP Session Modification Request
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

    // Handle Create operations (3GPP TS 29.244 Section 8.2.2, 8.2.3, 8.2.4)
    if (!mod_req->pfcp_ies.create_pdrs.empty()) {
      Logger::upf_app().debug(
          "Adding %zu new PDRs", mod_req->pfcp_ies.create_pdrs.size());
      for (const auto& pdr : mod_req->pfcp_ies.create_pdrs) {
        session->pdrs.push_back(std::make_shared<pfcp::pfcp_pdr>(pdr));
      }
    }

    if (!mod_req->pfcp_ies.create_fars.empty()) {
      Logger::upf_app().debug(
          "Adding %zu new FARs", mod_req->pfcp_ies.create_fars.size());
      for (const auto& far : mod_req->pfcp_ies.create_fars) {
        session->fars.push_back(std::make_shared<pfcp::pfcp_far>(far));
      }
    }

    if (!mod_req->pfcp_ies.create_qers.empty()) {
      Logger::upf_app().debug(
          "Adding %zu new QERs", mod_req->pfcp_ies.create_qers.size());
      for (const auto& qer : mod_req->pfcp_ies.create_qers) {
        session->qers.push_back(std::make_shared<pfcp::pfcp_qer>(qer));
      }
    }

    // Handle Update operations (3GPP TS 29.244 Section 8.2.9, 8.2.10, 8.2.11)
    size_t updated_pdrs = HandlePdrUpdates(session, mod_req);
    size_t updated_fars = HandleFarUpdates(session, mod_req);
    size_t updated_qers = HandleQerUpdates(session, mod_req);

    // Handle Remove operations (3GPP TS 29.244 Section 8.2.16, 8.2.17, 8.2.18)
    size_t removed_pdrs = HandlePdrRemoval(session, mod_req);
    size_t removed_fars = HandleFarRemoval(session, mod_req);
    size_t removed_qers = HandleQerRemoval(session, mod_req);

    Logger::upf_app().info(
        "[N4] Session Modification: seid 0x%lx - "
        "Operations=[Create: %zu/%zu/%zu Update: %zu/%zu/%zu Remove: "
        "%zu/%zu/%zu] "
        "Units=[PDRs/FARs/QERs]",
        seid, mod_req->pfcp_ies.create_pdrs.size(),
        mod_req->pfcp_ies.create_fars.size(),
        mod_req->pfcp_ies.create_qers.size(), updated_pdrs, updated_fars,
        updated_qers, removed_pdrs, removed_fars, removed_qers);
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
// 3GPP TS 29.244 Section 7.5.5.2 - PFCP Session Deletion Request
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
// Reference: 3GPP TS 29.244 Section 5.2.1 - Packet Detection Rule
//------------------------------------------------------------------------------

// 3GPP TS 29.244 Section 8.2.2 - Create PDR
bool SessionManager::AddPdr(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_pdr> pdr) {
  if (!pdr) {
    Logger::upf_app().error("AddPdr: null PDR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSession(seid);
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
// 3GPP TS 29.244 Section 8.2.9 - Update PDR
bool SessionManager::UpdatePdr(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_pdr> pdr) {
  if (!pdr) {
    Logger::upf_app().error("UpdatePdr: null PDR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSession(seid);
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
// 3GPP TS 29.244 Section 8.2.16 - Remove PDR
bool SessionManager::RemovePdr(uint64_t seid, uint16_t pdr_id) {
  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSession(seid);
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
// Reference: 3GPP TS 29.244 Section 5.2.2 - Forwarding Action Rule
//------------------------------------------------------------------------------

// 3GPP TS 29.244 Section 8.2.3 - Create FAR
bool SessionManager::AddFar(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_far> far) {
  if (!far) {
    Logger::upf_app().error("AddFar: null FAR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSession(seid);
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
// 3GPP TS 29.244 Section 8.2.10 - Update FAR
bool SessionManager::UpdateFar(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_far> far) {
  if (!far) {
    Logger::upf_app().error("UpdateFar: null FAR");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSession(seid);
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
// 3GPP TS 29.244 Section 8.2.17 - Remove FAR
bool SessionManager::RemoveFar(uint64_t seid, uint32_t far_id) {
  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSession(seid);
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
// Reference: 3GPP TS 29.244 Section 5.2.4 - QoS Enforcement Rule
//------------------------------------------------------------------------------

// 3GPP TS 29.244 Section 8.2.4 - Create QER
bool SessionManager::AddQer(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_qer> qer) {
  if (!qer) {
    Logger::upf_app().error("AddQer: null QER");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSession(seid);
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
// 3GPP TS 29.244 Section 8.2.11 - Update QER
bool SessionManager::UpdateQer(
    uint64_t seid, std::shared_ptr<pfcp::pfcp_qer> qer) {
  if (!qer) {
    Logger::upf_app().error("UpdateQer: null QER");
    return false;
  }

  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSession(seid);
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
// 3GPP TS 29.244 Section 8.2.18 - Remove QER
bool SessionManager::RemoveQer(uint64_t seid, uint32_t qer_id) {
  try {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto session = GetSession(seid);
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
// 3GPP TS 29.281 - Retrieve TEID from session
uint32_t SessionManager::RetrieveTeid(
    std::shared_ptr<pfcp::pfcp_session> session) const {
  uint32_t teid = 0;

  for (const auto& pdr : session->pdrs_downlink) {
    std::shared_ptr<pfcp::pfcp_far> far;
    if (GetFarForPdr(session, pdr, far)) {
      pfcp::forwarding_parameters fwd_params;
      if (far->get(fwd_params) && fwd_params.outer_header_creation.first) {
        teid = fwd_params.outer_header_creation.second.teid;
        break;
      }
    }
  }

  return teid;
}

//------------------------------------------------------------------------------
// Helper function to find the Uplink TEID to update
uint64_t SessionManager::FindUplinkTeid(uint64_t seid) const {
  for (const auto& session : sessions_) {
    if (session->get_up_seid() != seid) {
      continue;  // Skip to the next session if not matching seid
    }

    for (const auto& pdr : session->pdrs) {
      pfcp::pdi pdi;
      if (pdr->get(pdi)) {
        pfcp::source_interface_t source_interface;
        if (pdi.get(source_interface) &&
            source_interface.interface_value == pfcp::INTERFACE_VALUE_ACCESS) {
          return session->teid_uplink.teid;
        }
      }
    }
  }

  return 0;  // Return 0 if teid_uplink is not found
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
// Reference: 3GPP TS 29.244 Section 8.2.29 - Precedence
//------------------------------------------------------------------------------

void SessionManager::CategorizePdrs(
    std::shared_ptr<pfcp::pfcp_session> session) {
  // session->pdrs_uplink.clear();
  // session->pdrs_downlink.clear();
  // session->qers_uplink.clear();
  // session->qers_downlink.clear();

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

    // 3GPP TS 29.244 Section 8.2.62 - Source Interface
    switch (source_interface.interface_value) {
      case INTERFACE_VALUE_ACCESS: {
        session->pdrs_uplink.push_back(pdr);
        if (has_qer) {
          session->qers_uplink.push_back(qer);
        }
        break;
      }
      case INTERFACE_VALUE_CORE: {
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
    // Extract PDR ID
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

    // Update only fields present in update_pdr
    // All PFCP fields use std::pair<bool, T> where .first=present,
    // .second=value
    pfcp::precedence_t precedence;
    if (update_pdr.get(precedence)) {
      existing_pdr->precedence.first  = true;
      existing_pdr->precedence.second = precedence;
    }

    pfcp::pdi pdi;
    if (update_pdr.get(pdi)) {
      existing_pdr->pdi.first = true;

      pfcp::source_interface_t source_if;
      if (pdi.get(source_if)) {
        existing_pdr->pdi.second.source_interface.first  = true;
        existing_pdr->pdi.second.source_interface.second = source_if;
      }

      pfcp::fteid_t fteid;
      if (pdi.get(fteid)) {
        existing_pdr->pdi.second.local_fteid.first  = true;
        existing_pdr->pdi.second.local_fteid.second = fteid;
      }

      pfcp::ue_ip_address_t ue_ip;
      if (pdi.get(ue_ip)) {
        existing_pdr->pdi.second.ue_ip_address.first  = true;
        existing_pdr->pdi.second.ue_ip_address.second = ue_ip;
      }

      pfcp::network_instance_t network_instance;
      if (pdi.get(network_instance)) {
        existing_pdr->pdi.second.network_instance.first  = true;
        existing_pdr->pdi.second.network_instance.second = network_instance;
      }

      pfcp::sdf_filter_t sdf_filter;
      if (pdi.get(sdf_filter)) {
        existing_pdr->pdi.second.sdf_filter.first  = true;
        existing_pdr->pdi.second.sdf_filter.second = sdf_filter;
      }
    }

    pfcp::outer_header_removal_t ohr;
    if (update_pdr.get(ohr)) {
      existing_pdr->outer_header_removal.first  = true;
      existing_pdr->outer_header_removal.second = ohr;
    }

    pfcp::far_id_t far_id;
    if (update_pdr.get(far_id)) {
      existing_pdr->far_id.first  = true;
      existing_pdr->far_id.second = far_id;
    }

    pfcp::qer_id_t qer_id;
    if (update_pdr.get(qer_id)) {
      existing_pdr->qer_id.first  = true;
      existing_pdr->qer_id.second = qer_id;
    }

    // Handle Activate Predefined Rules (3GPP TS 29.244 Table 7.5.4.2-1)
    if (update_pdr.has_activate_predefined_rules()) {
      const auto& activate_rules = update_pdr.get_activate_predefined_rules();
      for (const auto& rule : activate_rules) {
        Logger::upf_app().info(
            "Activating predefined rule '%s' for PDR %u in session " SEID_FMT,
            rule.predefined_rules_name.c_str(), pdr_id, session->get_up_seid());

        // TODO: Implement predefined rule activation logic
        // This typically involves:
        // 1. Looking up the predefined rule in configuration
        // 2. Applying the rule's policies to the PDR
        // 3. Updating BPF maps with the rule's parameters

        // Store the activation request in the PDR
        if (existing_pdr->activate_predefined_rules.first) {
          Logger::upf_app().warn(
              "PDR %u: Multiple activate_predefined_rules - implementation "
              "needed",
              pdr_id);
        } else {
          existing_pdr->activate_predefined_rules.first  = true;
          existing_pdr->activate_predefined_rules.second = rule;
        }
      }
    }

    // Handle Deactivate Predefined Rules (3GPP TS 29.244 Table 7.5.4.2-1)
    if (update_pdr.has_deactivate_predefined_rules()) {
      const auto& deactivate_rules =
          update_pdr.get_deactivate_predefined_rules();
      for (const auto& rule : deactivate_rules) {
        Logger::upf_app().info(
            "Deactivating predefined rule '%s' for PDR %u in session " SEID_FMT,
            rule.predefined_rules_name.c_str(), pdr_id, session->get_up_seid());

        // TODO: Implement predefined rule deactivation logic
        // This typically involves:
        // 1. Looking up the currently active predefined rule
        // 2. Removing the rule's policies from the PDR
        // 3. Updating BPF maps to remove the rule's parameters

        // Check if this rule is currently activated
        if (existing_pdr->activate_predefined_rules.first &&
            existing_pdr->activate_predefined_rules.second
                    .predefined_rules_name == rule.predefined_rules_name) {
          // Deactivate by clearing the field
          existing_pdr->activate_predefined_rules.first = false;
          Logger::upf_app().info(
              "Deactivated predefined rule '%s' for PDR %u",
              rule.predefined_rules_name.c_str(), pdr_id);
        } else {
          Logger::upf_app().warn(
              "PDR %u: Predefined rule '%s' not found for deactivation", pdr_id,
              rule.predefined_rules_name.c_str());
        }
      }

      pfcp::urr_id_t urr_id;
      if (update_pdr.get(urr_id)) {
        existing_pdr->urr_id.first  = true;
        existing_pdr->urr_id.second = urr_id;
      }

      updated_count++;
    }

    // Re-categorize and update BPF maps
    if (updated_count > 0) {
      CategorizePdrs(session);
      SortPdrs(session->pdrs_uplink);
      SortPdrs(session->pdrs_downlink);
      session_program_manager_->ModifyPipeline(session);
    }

    return updated_count;
  }
  return updated_count;
}

//------------------------------------------------------------------------------
size_t SessionManager::HandleFarUpdates(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_modification_request* mod_req) {
  size_t updated_count = 0;

  for (const auto& update_far : mod_req->pfcp_ies.update_fars) {
    // Extract FAR ID
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

    // Update only fields present in update_far
    // All PFCP fields use std::pair<bool, T> where .first=present,
    // .second=value

    pfcp::apply_action_t apply_action;
    if (update_far.get(apply_action)) {
      existing_far->apply_action = apply_action;
    }

    pfcp::update_forwarding_parameters update_fp;
    if (update_far.get(update_fp)) {
      existing_far->forwarding_parameters.first = true;

      pfcp::destination_interface_t dest_if;
      if (update_fp.get(dest_if)) {
        existing_far->forwarding_parameters.second.destination_interface.first =
            true;
        existing_far->forwarding_parameters.second.destination_interface
            .second = dest_if;
      }

      pfcp::network_instance_t network_instance;
      if (update_fp.get(network_instance)) {
        existing_far->forwarding_parameters.second.network_instance.first =
            true;
        existing_far->forwarding_parameters.second.network_instance.second =
            network_instance;
      }

      pfcp::outer_header_creation_t ohc;
      if (update_fp.get(ohc)) {
        existing_far->forwarding_parameters.second.outer_header_creation.first =
            true;
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
        existing_far->forwarding_parameters.second.forwarding_policy.first =
            true;
        existing_far->forwarding_parameters.second.forwarding_policy.second =
            fwd_policy;
      }

      pfcp::header_enrichment_t header_enrich;
      if (update_fp.get(header_enrich)) {
        existing_far->forwarding_parameters.second.header_enrichment.first =
            true;
        existing_far->forwarding_parameters.second.header_enrichment.second =
            header_enrich;
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
        existing_far->duplicating_parameters.second.forwarding_policy.first =
            true;
        existing_far->duplicating_parameters.second.forwarding_policy.second =
            fp;
      }
    }

    pfcp::bar_id_t bar_id;
    if (update_far.get(bar_id)) {
      existing_far->bar_id.first  = true;
      existing_far->bar_id.second = bar_id;
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
    // Extract QER ID
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

    // Update only fields present in update_qer
    // All PFCP fields use std::pair<bool, T> where .first=present,
    // .second=value

    pfcp::qer_correlation_id_t qer_corr_id;
    if (update_qer.get(qer_corr_id)) {
      existing_qer->qer_correlation_id.first  = true;
      existing_qer->qer_correlation_id.second = qer_corr_id;
    }

    pfcp::gate_status_t gate_status;
    if (update_qer.get(gate_status)) {
      existing_qer->gate_status.first  = true;
      existing_qer->gate_status.second = gate_status;
    }

    pfcp::mbr_t mbr;
    if (update_qer.get(mbr)) {
      existing_qer->maximum_bitrate.first  = true;
      existing_qer->maximum_bitrate.second = mbr;
    }

    pfcp::gbr_t gbr;
    if (update_qer.get(gbr)) {
      existing_qer->guaranteed_bitrate.first  = true;
      existing_qer->guaranteed_bitrate.second = gbr;
    }

    pfcp::qfi_t qfi;
    if (update_qer.get(qfi)) {
      existing_qer->qos_flow_id.first  = true;
      existing_qer->qos_flow_id.second = qfi;
    }

    pfcp::rqi_t rqi;
    if (update_qer.get(rqi)) {
      existing_qer->reflective_qos.first  = true;
      existing_qer->reflective_qos.second = rqi;
    }

    pfcp::paging_policy_indicator_t ppi;
    if (update_qer.get(ppi)) {
      existing_qer->paging_policy_indicator.first  = true;
      existing_qer->paging_policy_indicator.second = ppi;
    }

    pfcp::averaging_window_t avg_window;
    if (update_qer.get(avg_window)) {
      existing_qer->averaging_window.first  = true;
      existing_qer->averaging_window.second = avg_window;
    }

    updated_count++;
  }

  // Re-categorize and update BPF maps
  if (updated_count > 0) {
    CategorizePdrs(session);
    session_program_manager_->ModifyPipeline(session);
  }

  return updated_count;
}
