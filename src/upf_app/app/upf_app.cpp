/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "conversions.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "pfcp_switch.hpp"
#include "upf_app.hpp"
#include "upf_config.hpp"
#include "simple_switch.hpp"
#include "upf_n4.hpp"
#include "upf_nrf.hpp"
#include "UserPlaneComponent.h"

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <atomic>
#include <stdexcept>

using namespace pfcp;
using namespace oai::upf::app;
using namespace oai::config;
using namespace std;

// C includes

upf_n4* upf_n4_inst   = nullptr;
upf_n3* upf_n3_inst   = nullptr;
upf_nrf* upf_nrf_inst = nullptr;

extern itti_mw* itti_inst;
extern pfcp_switch* pfcp_switch_inst;
extern upf_app* upf_app_inst;
extern upf_config upf_cfg;

void upf_app_task(void*);

namespace {
// The DL buffer tick (pfcp_switch::dl_buffer_tick()) is a one-shot ITTI
// timer. It is re-armed first thing on each expiry, so a slow tick does not
// stretch the period.
//
// The state lives here rather than in upf_app because the task loop may see
// the first expiry before upf_app_inst is assigned. It is written on
// TASK_UPF_APP and by stop(), hence atomic. A tick that fires while stop()
// runs just runs once more and does not re-arm.
std::atomic<timer_id_t> dl_buffer_tick_timer{ITTI_INVALID_TIMER_ID};
std::atomic<bool> dl_buffer_tick_stopped{false};

void arm_dl_buffer_tick() {
  if (dl_buffer_tick_stopped.load()) return;
  dl_buffer_tick_timer.store(itti_inst->timer_setup(
      1, 0, TASK_UPF_APP, TASK_UPF_PFCP_SWITCH_DL_BUFFER_TICK));
}

//------------------------------------------------------------------------------
// replay_dl_flush -- send, or free, the packets a Session Modification took
// out of a session's DL buffer.
//
// Runs after the response is handed to TASK_UPF_N4: the gNB takes the new
// tunnel only once the SMF has its answer. Each packet goes back through the
// DL lookup, because the old rule may be gone. That lookup sends on the new
// FAR, or buffers the packet again if the UE is idle again. `released` skips
// the QoS meter, so a packet that waited for paging is not delayed again.
// Packets of a DISCARD or KEEP verdict are only freed.
//------------------------------------------------------------------------------
void replay_dl_flush(uint64_t seid, oai::upf::dl_flush_result& f) {
  if (f.verdict != oai::upf::dl_verdict::flush || f.removed.empty()) return;
  auto& store = pfcp_switch_inst->dl_buffer();
  size_t sent = 0, dropped = 0, rebuffered = 0;
  for (auto& pkt : f.removed) {
    // No N3 sender (eBPF datapath): the lookup could not forward it.
    const oai::upf::dl_outcome r =
        upf_n3_inst ? pfcp_switch_inst->pfcp_session_look_up_pack_in_core(
                          reinterpret_cast<const char*>(pkt.data()), pkt.len,
                          /*released=*/true) :
                      oai::upf::dl_outcome::dropped;
    store.note_replay(r);
    switch (r) {
      case oai::upf::dl_outcome::sent:
        sent++;
        break;
      case oai::upf::dl_outcome::dropped:
        dropped++;
        break;
      case oai::upf::dl_outcome::rebuffered:
        rebuffered++;
        break;
    }
  }
  f.removed.clear();
  Logger::pfcp_switch().info(
      "DL buffer seid " SEID_FMT
      ": replay sent %zu, dropped %zu, rebuffered %zu",
      seid, sent, dropped, rebuffered);
}
}  // namespace

//------------------------------------------------------------------------------
void upf_app_task(void* args_p) {
  const task_id_t task_id = TASK_UPF_APP;

  const oai::utils::thread_sched_params* const sched_params =
      (const oai::utils::thread_sched_params* const) args_p;

  sched_params->apply(task_id, Logger::upf_app());

  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto* msg                            = shared_msg.get();
    switch (msg->msg_type) {
      case N3_ECHO_REQUEST:
        upf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n3_echo_request>(shared_msg));
        break;

      case N4_SESSION_ESTABLISHMENT_REQUEST:
        upf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n4_session_establishment_request>(
                shared_msg));
        break;

      case N4_SESSION_MODIFICATION_REQUEST:
        upf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n4_session_modification_request>(
                shared_msg));
        break;

      case N4_SESSION_DELETION_REQUEST:
        upf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n4_session_deletion_request>(
                shared_msg));
        break;

      case N4_SESSION_REPORT_RESPONSE:
        upf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n4_session_report_response>(
                shared_msg));
        break;

      case N4_DL_NOTIFY_REARM:
        // TASK_UPF_N4 gave up on a DL Data Report (the SMF never answered).
        // This task owns the rules, so the PDR's notification latch is
        // released here. It is found by PDR ID because the report carries no
        // uid, which also finds the rule after an Update PDR.
        if (auto* m = dynamic_cast<itti_n4_dl_notify_rearm*>(msg)) {
          const bool rearmed =
              pfcp_switch_inst && pfcp_switch_inst->rearm_dl_notification(
                                      m->up_seid, std::nullopt, m->pdr_id);
          Logger::upf_app().debug(
              "Received N4_DL_NOTIFY_REARM seid " SEID_FMT " pdr %u: %s",
              m->up_seid, m->pdr_id,
              rearmed ? "latch re-armed" : "nothing to re-arm");
        }
        break;

      case TIME_OUT:
        if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
          switch (to->arg1_user) {
            case TASK_UPF_PFCP_SWITCH_MIN_COMMIT_INTERVAL:
              // pfcp_switch_inst->time_out_min_commit_interval(to->timer_id);
              break;
            case TASK_UPF_PFCP_SWITCH_MAX_COMMIT_INTERVAL:
              // pfcp_switch_inst->time_out_max_commit_interval(to->timer_id);
              break;
            case TASK_UPF_PFCP_SWITCH_DL_BUFFER_TICK:
              arm_dl_buffer_tick();
              if (pfcp_switch_inst) pfcp_switch_inst->dl_buffer_tick();
              break;
            default:;
          }
        }
        break;

      case TERMINATE:
        if (itti_msg_terminate* terminate =
                dynamic_cast<itti_msg_terminate*>(msg)) {
          Logger::upf_app().info("Received terminate message");
          return;
        }
        break;

      case HEALTH_PING:
        break;

      default:
        Logger::upf_app().info(
            "no handler for ITTI msg type %d", msg->msg_type);
    }
  } while (true);
}

//------------------------------------------------------------------------------
upf_app::upf_app(const std::string& config_file) {
  Logger::upf_app().startup("UPF initialization started");
  upf_cfg.execute();

  if (itti_inst->create_task(
          TASK_UPF_APP, upf_app_task, &upf_cfg.itti.upf_app_sched_params)) {
    Logger::upf_app().error("Cannot create task TASK_UPF_APP");
    throw std::runtime_error("Cannot create task TASK_UPF_APP");
  }
  try {
    upf_n4_inst = new upf_n4();
  } catch (std::exception& e) {
    Logger::upf_app().error("Cannot create UPF_N4: %s", e.what());
    throw;
  }
  if (not upf_cfg.enable_bpf_datapath) {
    try {
      upf_n3_inst = new upf_n3();
    } catch (std::exception& e) {
      Logger::upf_app().error("Cannot create UPF_N3: %s", e.what());
      throw;
    }
  } else if (upf_cfg.enable_bar and upf_cfg.enable_dl_buffering) {
    // XDP owns N3 on the eBPF datapath, but the DL buffer replay (after the
    // Session Modification that ends buffering) is sent from userspace. Give
    // it a sender that opens no listener on 2152.
    try {
      upf_n3_inst = new upf_n3(upf_n3::tx_only_t{});
    } catch (std::exception& e) {
      Logger::upf_app().error(
          "Cannot create transmit-only UPF_N3: %s", e.what());
      throw;
    }
  }
  try {
    pfcp_switch_inst = new pfcp_switch();
  } catch (std::exception& e) {
    Logger::upf_app().error("Cannot create PFCP_SWITCH: %s", e.what());
    throw;
  }
  // Armed whether or not DL buffering is enabled: the tick also releases the
  // latch of a DL Data Report that could not be sent.
  arm_dl_buffer_tick();
  try {
    if (upf_cfg.enable_5g_features and upf_cfg.register_nrf)
      upf_nrf_inst = new upf_nrf();
  } catch (std::exception& e) {
    Logger::upf_app().error("Cannot create UPF_NRF: %s", e.what());
    throw;
  }
  // Logger::upf_app().startup("Started");
}

//------------------------------------------------------------------------------
upf_app::~upf_app() {
  if (upf_n3_inst) {
    delete upf_n3_inst;
  }
  if (upf_n4_inst) {
    delete upf_n4_inst;
  }
  if (upf_nrf_inst) {
    delete upf_nrf_inst;
  }
  if (pfcp_switch_inst) {
    delete pfcp_switch_inst;
  }
}

//------------------------------------------------------------------------------
void upf_app::stop() {
  if (upf_nrf_inst) {
    upf_nrf_inst->deregister_to_nrf();
  }
  dl_buffer_tick_stopped.store(true);
  itti_inst->timer_remove(dl_buffer_tick_timer.exchange(ITTI_INVALID_TIMER_ID));
  // The AF_XDP thread enqueues into pfcp_switch, which ~upf_app deletes, so
  // stop it first. UserPlaneComponent::TearDown() normally stopped it
  // already; stopping twice is harmless.
  if (upf_cfg.enable_bpf_datapath) {
    UserPlaneComponent::GetInstance().StopXskConsumer();
  }
  // TODO: upf_n4, pfcp_switch
}

//------------------------------------------------------------------------------
void upf_app::handle_itti_msg(std::shared_ptr<itti_n3_echo_request> m) {
  Logger::upf_app().debug("Received %s ", m->get_msg_name());
  itti_n3_echo_response* n3_resp =
      new itti_n3_echo_response(TASK_UPF_APP, TASK_UPF_N3);

  // May insert a call to a function here(throttle for example)
  n3_resp->gtp_ies.r_endpoint      = m->gtp_ies.r_endpoint;
  n3_resp->gtp_ies.teid            = m->gtp_ies.teid;
  n3_resp->gtp_ies.sequence_number = m->gtp_ies.sequence_number;

  std::shared_ptr<itti_n3_echo_response> msg =
      std::shared_ptr<itti_n3_echo_response>(n3_resp);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::upf_app().error(
        "Could not send ITTI message %s to task TASK_UPF_N3",
        n3_resp->get_msg_name());
  }
}
//------------------------------------------------------------------------------
void upf_app::handle_itti_msg(
    std::shared_ptr<itti_n4_session_establishment_request> m) {
  Logger::upf_app().info("");
  // Logger::upf_app().info(
  //     "┌───────────────────────────────────────────────────────────────────────"
  //     "──────┐");
  Logger::upf_app().info(
      "╔═══════════════════════════════════════════════════════════════════════"
      "══════╗");
  Logger::upf_app().info(
      "│             Received N4_SESSION_ESTABLISHMENT_REQUEST seid"
      " " SEID_FMT
      "        "
      "      │",
      m->seid);
  Logger::upf_app().info(
      "╚═══════════════════════════════════════════════════════════════════════"
      "══════╝");
  // Logger::upf_app().info(
  //     "└───────────────────────────────────────────────────────────────────────"
  //     "──────┘");

  itti_n4_session_establishment_response* n4_resp =
      new itti_n4_session_establishment_response(TASK_UPF_APP, TASK_UPF_N4);
  pfcp_switch_inst->handle_pfcp_session_establishment_request(m, n4_resp);

  pfcp::node_id_t node_id = {};
  upf_cfg.get_pfcp_node_id(node_id);
  n4_resp->pfcp_ies.set(node_id);

  n4_resp->trxn_id = m->trxn_id;
  n4_resp->seid    = m->pfcp_ies.cp_fseid.second
                      .seid;  // Mandatory IE, but... may be bad to do this
  n4_resp->r_endpoint = m->r_endpoint;
  n4_resp->l_endpoint = m->l_endpoint;
  std::shared_ptr<itti_n4_session_establishment_response> msg =
      std::shared_ptr<itti_n4_session_establishment_response>(n4_resp);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::upf_app().error(
        "Could not send ITTI message %s to task TASK_UPF_N4",
        n4_resp->get_msg_name());
  }
}
//------------------------------------------------------------------------------
void upf_app::handle_itti_msg(
    std::shared_ptr<itti_n4_session_modification_request> m) {
  Logger::upf_app().info("");
  // Logger::upf_app().info(
  //     "┌───────────────────────────────────────────────────────────────────────"
  //     "──────┐");
  Logger::upf_app().info(
      "╔═══════════════════════════════════════════════════════════════════════"
      "══════╗");
  Logger::upf_app().info(
      "│             Received N4_SESSION_MODIFICATION_REQUEST seid"
      " " SEID_FMT
      "        "
      "       │",
      m->seid);
  Logger::upf_app().info(
      "╚═══════════════════════════════════════════════════════════════════════"
      "══════╝");
  // Logger::upf_app().info(
  //     "└───────────────────────────────────────────────────────────────────────"
  //     "──────┘");

  itti_n4_session_modification_response* n4_resp =
      new itti_n4_session_modification_response(TASK_UPF_APP, TASK_UPF_N4);
  oai::upf::dl_flush_result flush;
  pfcp_switch_inst->handle_pfcp_session_modification_request(
      m, n4_resp, &flush);

  n4_resp->trxn_id    = m->trxn_id;
  n4_resp->r_endpoint = m->r_endpoint;
  n4_resp->l_endpoint = m->l_endpoint;
  std::shared_ptr<itti_n4_session_modification_response> msg =
      std::shared_ptr<itti_n4_session_modification_response>(n4_resp);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::upf_app().error(
        "Could not send ITTI message %s to task TASK_UPF_N4",
        n4_resp->get_msg_name());
  }
  replay_dl_flush(m->seid, flush);
}
//------------------------------------------------------------------------------
void upf_app::handle_itti_msg(
    std::shared_ptr<itti_n4_session_deletion_request> m) {
  Logger::upf_app().info("");
  // Logger::upf_app().info(
  //     "┌───────────────────────────────────────────────────────────────────────"
  //     "──────┐");
  Logger::upf_app().info(
      "╔═══════════════════════════════════════════════════════════════════════"
      "══════╗");
  Logger::upf_app().info(
      "│             Received N4_SESSION_DELETION_REQUEST seid"
      " " SEID_FMT
      "        "
      "       │",
      m->seid);
  Logger::upf_app().info(
      "╚═══════════════════════════════════════════════════════════════════════"
      "══════╝");
  // Logger::upf_app().info(
  //     "└───────────────────────────────────────────────────────────────────────"
  //     "──────┘");
  itti_n4_session_deletion_response* n4_resp =
      new itti_n4_session_deletion_response(TASK_UPF_APP, TASK_UPF_N4);
  pfcp_switch_inst->handle_pfcp_session_deletion_request(m, n4_resp);

  n4_resp->trxn_id    = m->trxn_id;
  n4_resp->r_endpoint = m->r_endpoint;
  n4_resp->l_endpoint = m->l_endpoint;
  std::shared_ptr<itti_n4_session_deletion_response> msg =
      std::shared_ptr<itti_n4_session_deletion_response>(n4_resp);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::upf_app().error(
        "Could not send ITTI message %s to task TASK_UPF_N4",
        n4_resp->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void upf_app::handle_itti_msg(
    std::shared_ptr<itti_n4_session_report_response> m) {
  Logger::upf_app().info("");
  // Logger::upf_app().info(
  //     "┌───────────────────────────────────────────────────────────────────────"
  //     "──────┐");
  Logger::upf_app().info(
      "╔═══════════════════════════════════════════════════════════════════════"
      "══════╗");
  Logger::upf_app().info(
      "│             Received N4_SESSION_REPORT_RESPONSE seid"
      " " SEID_FMT
      "        "
      "       │",
      m->seid);
  Logger::upf_app().info(
      "╚═══════════════════════════════════════════════════════════════════════"
      "══════╝");
  // Logger::upf_app().info(
  //     "└───────────────────────────────────────────────────────────────────────"
  //     "──────┘");
}
