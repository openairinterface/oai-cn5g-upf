/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DpdkDatapath.h"

#include <set>

#include "Configuration.h"
#include "DpdkEal.h"
#include "DpdkFastPath.h"
#include "DpdkSessionStore.h"
#include "DpdkSessionTables.h"
#include "SessionManager.h"
#include "logger.hpp"
#include "pfcp_session.hpp"
#include "upf_config.hpp"
#include "upf_network_config.h"
#include "upf_pfcp_association.hpp"

using namespace pfcp;
using namespace oai::upf::app;

extern oai::config::upf_config upf_cfg;

namespace {

/// Report a rejected rule back to the SMF (§8.2.80 Failed Rule ID).
template <typename ResponseMsg>
void FailRule(ResponseMsg* response, uint8_t rule_type, uint32_t rule_id) {
  pfcp::failed_rule_id_t failed_rule = {};
  failed_rule.rule_id_type           = rule_type;
  failed_rule.rule_id_value          = rule_id;
  response->pfcp_ies.set(failed_rule);
}

/**
 * @brief Apply the Remove <rule> IEs of one rule kind.
 * @param id_of Extracts the rule id of an IE, for the Failed Rule ID report.
 * @return false on the first hard failure (the caller then stops).
 */
template <typename ResponseMsg, typename Rules, typename IdOf>
bool RemoveRules(
    pfcp::pfcp_session* session, Rules& rules, uint8_t rule_type, IdOf id_of,
    pfcp::cause_t& cause, pfcp::offending_ie_t& offending_ie,
    ResponseMsg* response) {
  for (auto& rule : rules) {
    if (not session->remove(rule, cause, offending_ie.offending_ie) &&
        cause.cause_value == CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
      FailRule(response, rule_type, id_of(rule));
      return false;
    }
  }
  return true;
}

/**
 * @brief Apply the Update <rule> IEs of one rule kind.
 *
 * A rejected rule is reported and its cause propagated, but the remaining
 * rules are still applied (§7.5.5).
 */
template <typename ResponseMsg, typename Rules, typename IdOf>
void UpdateRules(
    pfcp::pfcp_session* session, Rules& rules, uint8_t rule_type, IdOf id_of,
    pfcp::cause_t& cause, ResponseMsg* response) {
  for (auto& rule : rules) {
    uint8_t rule_cause = CAUSE_VALUE_REQUEST_ACCEPTED;
    if (not session->update(rule, rule_cause)) {
      cause.cause_value = rule_cause;
      FailRule(response, rule_type, id_of(rule));
    }
  }
}

}  // namespace

//------------------------------------------------------------------------------
DpdkDatapath::DpdkDatapath() {}

//------------------------------------------------------------------------------
DpdkDatapath::~DpdkDatapath() {
  TearDown();
}



//------------------------------------------------------------------------------
void DpdkDatapath::Setup() {
  if (!DpdkEal::IsInitialized()) {
    throw std::runtime_error(
        "DPDK: EAL is not initialised; DpdkEal::Init must run before the "
        "datapath is built");
  }

  Logger::upf_app().info("Setting up DPDK datapath");

  // Single write-point upf_cfg → upf::g_net_cfg, shared with the eBPF flavour.
  Configuration::BuildNetworkConfig();

  Logger::upf_app().info(
      "DPDK datapath: N3 = %s, N6 = %s, max PDU sessions = %u",
      upf::GetN3Iface().c_str(), upf::GetN6Iface().c_str(),
      upf::g_net_cfg.max_pdu_sessions);

  session_store_  = std::make_shared<DpdkSessionStore>();
  session_tables_ = std::make_shared<DpdkSessionTables>();

  // Brings up the ports, sizes the tables and starts polling.
  fast_path_ = std::make_unique<DpdkFastPath>(*session_tables_);
  fast_path_->Setup(upf::g_net_cfg.max_pdu_sessions);

  session_manager_ = std::make_shared<SessionManager>(session_tables_);

  is_setup_ = true;
  Logger::upf_app().info("DPDK datapath ready");
}

//------------------------------------------------------------------------------
void DpdkDatapath::LogStatistics() const {
  if (fast_path_) fast_path_->LogStatistics();
}

//------------------------------------------------------------------------------
void DpdkDatapath::TearDown() {
  if (!is_setup_) return;
  Logger::upf_app().info("Tearing down DPDK datapath");

  // Stop polling first: no lcore may still be reading what we free below.
  if (fast_path_) {
    fast_path_->TearDown();
    fast_path_.reset();
  }

  if (session_tables_) {
    session_tables_->TearDown();
  }
  session_manager_.reset();
  session_tables_.reset();
  session_store_.reset();
  is_setup_ = false;
}

//------------------------------------------------------------------------------
void DpdkDatapath::SyncDatapath(
    pfcp::pfcp_session* session,
    itti_n4_session_establishment_request* establishment,
    itti_n4_session_modification_request* modification,
    itti_n4_session_deletion_request* deletion) {
  // Hand the backend a detached snapshot so it never races against the next
  // N4 message mutating the live session.
  std::shared_ptr<pfcp::pfcp_session> snapshot =
      std::make_shared<pfcp::pfcp_session>(*session);

  SessionOperationResult result =
      establishment ?
          session_manager_->EstablishSession(
              snapshot, establishment, nullptr, nullptr) :
          (modification ? session_manager_->ModifySession(
                              snapshot, nullptr, modification, nullptr) :
                          session_manager_->RemoveSession(
                              snapshot, nullptr, nullptr, deletion));

  if (!result.success) {
    Logger::upf_app().error(
        "DPDK datapath operation failed: %s (SEID: 0x%lx)",
        result.message.c_str(), result.seid);
  }
}

//------------------------------------------------------------------------------
// Create PDR/FAR/QER/URR/BAR/MAR — TS 29.244 §7.5.2.2-8, §7.5.4.2-15.
// FARs first: a Create PDR refers to its FAR by ID.
//------------------------------------------------------------------------------
template <typename RequestIes, typename ResponseMsg>
bool DpdkDatapath::ApplyCreateIes(
    pfcp::pfcp_session* session, RequestIes& ies, ResponseMsg* response,
    pfcp::cause_t& cause, pfcp::offending_ie_t& offending_ie) {
  for (auto& cr_far : ies.create_fars) {
    if (not session->create(cr_far, cause, offending_ie.offending_ie)) {
      return false;
    }
  }

  // QERs before the PDRs that reference them by ID (§8.2.75).
  std::set<uint32_t> created_qer_ids;
  if (upf_cfg.enable_qos) {
    for (auto& cr_qer : ies.create_qers) {
      if (not session->create(cr_qer, cause, offending_ie.offending_ie)) {
        return false;
      }
      created_qer_ids.insert(cr_qer.qer_id.second.qer_id);
    }
  }

  for (auto& cr_pdr : ies.create_pdrs) {
    pfcp::far_id_t far_id = {};
    if (not cr_pdr.get(far_id)) {
      cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
      offending_ie.offending_ie = PFCP_IE_FAR_ID;
      return false;
    }
    pfcp::create_far cr_far = {};
    if (not ies.get(far_id, cr_far)) {
      cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
      offending_ie.offending_ie = PFCP_IE_CREATE_FAR;
      return false;
    }

    // A PDR may only reference a QER the same request creates (§7.5.2.2).
    if (upf_cfg.enable_qos) {
      pfcp::qer_id_t qer_id = {};
      if (cr_pdr.get(qer_id) &&
          created_qer_ids.count(qer_id.qer_id) == 0) {
        cause.cause_value         = CAUSE_VALUE_CONDITIONAL_IE_MISSING;
        offending_ie.offending_ie = PFCP_IE_CREATE_QER;
        return false;
      }
    }

    pfcp::fteid_t allocated_fteid = {};
    if (not session->create(
            cr_pdr, cause, offending_ie.offending_ie, allocated_fteid)) {
      return false;
    }

    // Report the PDR (and the F-TEID we allocated for it) back to the SMF.
    pfcp::created_pdr created_pdr = {};
    created_pdr.set(cr_pdr.pdr_id.second);
    if (allocated_fteid.v4 || allocated_fteid.v6) {
      created_pdr.set(allocated_fteid);
    }
    response->pfcp_ies.set(created_pdr);
  }

  if (upf_cfg.enable_urr) {
    for (auto& cr_urr : ies.create_urrs) {
      if (not session->create(cr_urr, cause, offending_ie.offending_ie)) {
        return false;
      }
    }
  }

  // common-src models Create BAR as a singular std::pair, not a vector.
  if (upf_cfg.enable_bar && ies.create_bar.first) {
    if (not session->create(
            ies.create_bar.second, cause, offending_ie.offending_ie)) {
      return false;
    }
  }

  if (upf_cfg.enable_mar) {
    for (auto& cr_mar : ies.create_mars) {
      if (not session->create(cr_mar, cause, offending_ie.offending_ie)) {
        return false;
      }
    }
  }

  return true;
}

//------------------------------------------------------------------------------
// PFCP Session Establishment — TS 29.244 §7.5.2
//------------------------------------------------------------------------------
void DpdkDatapath::HandleSessionEstablishment(
    std::shared_ptr<itti_n4_session_establishment_request> request,
    itti_n4_session_establishment_response* response) {
  itti_n4_session_establishment_request* req = request.get();
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};
  pfcp::fseid_t cp_fseid            = {};

  if (not req->pfcp_ies.get(cp_fseid)) {
    // Should have been caught by the PFCP decoder.
    cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie.offending_ie = PFCP_IE_F_SEID;
    response->pfcp_ies.set(cause);
    response->pfcp_ies.set(offending_ie);
    return;
  }

  if (session_store_->FindByCpFseid(cp_fseid)) {
    Logger::upf_n4().warn(
        "DPDK: session with CP F-SEID 0x%lx already exists", cp_fseid.seid);
    cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
    response->pfcp_ies.set(cause);
    return;
  }

  auto session = std::make_shared<pfcp::pfcp_session>(
      cp_fseid, session_store_->GenerateSeid(), session_store_.get());

  if (not ApplyCreateIes(
          session.get(), req->pfcp_ies, response, cause, offending_ie)) {
    session->cleanup();
    response->pfcp_ies.set(cause);
    if (cause.cause_value == CAUSE_VALUE_MANDATORY_IE_MISSING ||
        cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING) {
      response->pfcp_ies.set(offending_ie);
    }
    return;
  }

  SyncDatapath(session.get(), req, nullptr, nullptr);
  session_store_->AddSession(session);

  // UP F-SEID the SMF must use for this session (§8.2.37).
  pfcp::fseid_t up_fseid = {};
  upf_cfg.get_pfcp_fseid(up_fseid);
  up_fseid.seid = session->get_up_seid();
  response->pfcp_ies.set(up_fseid);
  response->pfcp_ies.set(cause);

  pfcp::node_id_t node_id = {};
  req->pfcp_ies.get(node_id);
  pfcp_associations::get_instance().notify_add_session(node_id, cp_fseid);

  Logger::upf_n4().info(
      "DPDK: session established, UP SEID 0x%lx (CP F-SEID 0x%lx)",
      session->get_up_seid(), cp_fseid.seid);
}

//------------------------------------------------------------------------------
// PFCP Session Modification — TS 29.244 §7.5.4
// Remove, then create, then update; the datapath is synced once at the end.
//------------------------------------------------------------------------------
void DpdkDatapath::HandleSessionModification(
    std::shared_ptr<itti_n4_session_modification_request> request,
    itti_n4_session_modification_response* response) {
  itti_n4_session_modification_request* req = request.get();
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};

  std::shared_ptr<pfcp::pfcp_session> session =
      session_store_->FindByUpSeid(req->seid);
  if (!session) {
    cause.cause_value = CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
    response->pfcp_ies.set(cause);
    return;
  }

  pfcp::fseid_t new_cp_fseid = {};
  if (req->pfcp_ies.get(new_cp_fseid)) {
    // TODO(dpdk): re-index the store when the SMF moves the CP F-SEID.
    Logger::upf_n4().warn("DPDK: CP F-SEID update in modification request");
    session->cp_fseid = new_cp_fseid;
  }
  response->seid = session->cp_fseid.seid;

  // ---- Remove rules (§7.5.4.5-15) -----------------------------------------
  bool ok = RemoveRules(
      session.get(), req->pfcp_ies.remove_pdrs, FAILED_RULE_ID_TYPE_PDR,
      [](const pfcp::remove_pdr& r) { return r.pdr_id.second.rule_id; }, cause,
      offending_ie, response);
  if (ok) {
    ok = RemoveRules(
        session.get(), req->pfcp_ies.remove_fars, FAILED_RULE_ID_TYPE_FAR,
        [](const pfcp::remove_far& r) { return r.far_id.second.far_id; }, cause,
        offending_ie, response);
  }
  if (ok && upf_cfg.enable_qos) {
    ok = RemoveRules(
        session.get(), req->pfcp_ies.remove_qers, FAILED_RULE_ID_TYPE_QER,
        [](const pfcp::remove_qer& r) { return r.qer_id.second.qer_id; }, cause,
        offending_ie, response);
  }
  if (ok && upf_cfg.enable_urr) {
    ok = RemoveRules(
        session.get(), req->pfcp_ies.remove_urrs, FAILED_RULE_ID_TYPE_URR,
        [](const pfcp::remove_urr& r) { return r.urr_id.second.urr_id; }, cause,
        offending_ie, response);
  }
  if (ok && upf_cfg.enable_mar) {
    ok = RemoveRules(
        session.get(), req->pfcp_ies.remove_mars, FAILED_RULE_ID_TYPE_MAR,
        [](const pfcp::remove_mar& r) { return r.mar_id.second.mar_id; }, cause,
        offending_ie, response);
  }
  // common-src models Remove BAR as a singular std::pair, not a vector.
  if (ok && upf_cfg.enable_bar && req->pfcp_ies.remove_bar.first) {
    const pfcp::remove_bar& bar = req->pfcp_ies.remove_bar.second;
    if (not session->remove(bar, cause, offending_ie.offending_ie) &&
        cause.cause_value == CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
      FailRule(response, FAILED_RULE_ID_TYPE_BAR, bar.bar_id.second.bar_id);
    }
  }

  // ---- Create rules (§7.5.4.2-14) -----------------------------------------
  if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
    ApplyCreateIes(
        session.get(), req->pfcp_ies, response, cause, offending_ie);
  }

  // ---- Update rules (§7.5.4.3-16) -----------------------------------------
  if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
    UpdateRules(
        session.get(), req->pfcp_ies.update_pdrs, FAILED_RULE_ID_TYPE_PDR,
        [](const pfcp::update_pdr& r) { return r.pdr_id.second.rule_id; },
        cause, response);
    UpdateRules(
        session.get(), req->pfcp_ies.update_fars, FAILED_RULE_ID_TYPE_FAR,
        [](const pfcp::update_far& r) { return r.far_id.far_id; }, cause,
        response);
    if (upf_cfg.enable_qos) {
      UpdateRules(
          session.get(), req->pfcp_ies.update_qers, FAILED_RULE_ID_TYPE_QER,
          [](const pfcp::update_qer& r) { return r.qer_id.second.qer_id; },
          cause, response);
    }
    if (upf_cfg.enable_urr) {
      UpdateRules(
          session.get(), req->pfcp_ies.update_urrs, FAILED_RULE_ID_TYPE_URR,
          [](const pfcp::update_urr& r) { return r.urr_id.second.urr_id; },
          cause, response);
    }
    if (upf_cfg.enable_mar) {
      UpdateRules(
          session.get(), req->pfcp_ies.update_mars, FAILED_RULE_ID_TYPE_MAR,
          [](const pfcp::update_mar& r) { return r.mar_id.second.mar_id; },
          cause, response);
    }
    // common-src models Update BAR as a singular std::pair, not a vector.
    if (upf_cfg.enable_bar && req->pfcp_ies.update_bar.first) {
      const update_bar_within_pfcp_session_modification_request& bar =
          req->pfcp_ies.update_bar.second;
      uint8_t rule_cause = CAUSE_VALUE_REQUEST_ACCEPTED;
      if (not session->update(bar, rule_cause)) {
        cause.cause_value = rule_cause;
        FailRule(response, FAILED_RULE_ID_TYPE_BAR, bar.bar_id.second.bar_id);
      }
    }
  }

  SyncDatapath(session.get(), nullptr, req, nullptr);

  response->pfcp_ies.set(cause);
  if (cause.cause_value == CAUSE_VALUE_MANDATORY_IE_MISSING ||
      cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING) {
    response->pfcp_ies.set(offending_ie);
  }
}

//------------------------------------------------------------------------------
// PFCP Session Deletion — TS 29.244 §7.5.6
//------------------------------------------------------------------------------
void DpdkDatapath::HandleSessionDeletion(
    std::shared_ptr<itti_n4_session_deletion_request> request,
    itti_n4_session_deletion_response* response) {
  itti_n4_session_deletion_request* req = request.get();
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};

  std::shared_ptr<pfcp::pfcp_session> session =
      session_store_->FindByUpSeid(req->seid);
  if (!session) {
    cause.cause_value = CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
    response->pfcp_ies.set(cause);
    return;
  }

  const pfcp::fseid_t cp_fseid = session->cp_fseid;
  response->seid               = cp_fseid.seid;

  SyncDatapath(session.get(), nullptr, nullptr, req);
  session_store_->RemoveByUpSeid(session->get_up_seid());
  session->cleanup();

  pfcp_associations::get_instance().notify_del_session(cp_fseid);
  response->pfcp_ies.set(cause);

  Logger::upf_n4().info(
      "DPDK: session 0x%lx deleted", (uint64_t) req->seid);
}

//------------------------------------------------------------------------------
// PFCP association teardown — TS 29.244 §6.2.6
//------------------------------------------------------------------------------
void DpdkDatapath::RemoveSession(const pfcp::fseid_t& cp_fseid) {
  std::shared_ptr<pfcp::pfcp_session> session =
      session_store_->FindByCpFseid(cp_fseid);
  if (!session) return;

  // Goes through SessionManager so its rule state is dropped too, not just
  // the datapath tables.
  session_manager_->DeleteSession(session->get_up_seid());
  session_store_->RemoveByUpSeid(session->get_up_seid());
  session->cleanup();
}
