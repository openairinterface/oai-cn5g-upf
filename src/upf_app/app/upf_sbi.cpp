/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "upf_sbi.hpp"

#include <nlohmann/json.hpp>
#include <stdexcept>

#include "3gpp_29.500.h"
#include "3gpp_29.510.h"
#include "http_client.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "upf.h"
#include "upf_config.hpp"

using namespace oai::config;
using namespace oai::upf::app;
using json = nlohmann::json;

extern itti_mw* itti_inst;
extern upf_sbi* upf_sbi_inst;
extern upf_config upf_cfg;
extern std::shared_ptr<oai::http::http_client> http_client_inst;
void upf_sbi_task(void*);

namespace {
std::shared_ptr<oai::sba::nf_event> borrowed_nf_event() {
  return std::shared_ptr<oai::sba::nf_event>(
      &oai::sba::nf_event::get_instance(), [](oai::sba::nf_event*) {});
}
}  // namespace

//------------------------------------------------------------------------------
void upf_sbi_task(void* args_p) {
  const task_id_t task_id = TASK_UPF_SBI;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto* msg                            = shared_msg.get();
    switch (msg->msg_type) {
      case TIME_OUT:
        if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
          Logger::upf_app().info("TIME-OUT event timer id %d", to->timer_id);
          switch (to->arg1_user) {
            case TASK_UPF_SBI_TIMEOUT_NRF_HEARTBEAT:
              upf_sbi_inst->timer_nrf_heartbeat_timeout(
                  to->timer_id, to->arg2_user);
              break;
            case TASK_UPF_SBI_TIMEOUT_NRF_DEREGISTRATION:
              upf_sbi_inst->timer_nrf_deregistration(
                  to->timer_id, to->arg2_user);
              break;
            case TASK_UPF_SBI_TIMEOUT_NRF_REGISTRATION:
              upf_sbi_inst->timer_nrf_registration(to->timer_id, to->arg2_user);
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

      default:
        Logger::upf_app().info("no handler for msg type %d", msg->msg_type);
    }

  } while (true);
}

//------------------------------------------------------------------------------
upf_sbi::upf_sbi()
    : oai::sba::nf_service(borrowed_nf_event(), http_client_inst) {
  Logger::upf_app().startup("Starting...");

  if (itti_inst->create_task(TASK_UPF_SBI, upf_sbi_task, nullptr)) {
    Logger::upf_app().error("Cannot create task TASK_UPF_SBI");
    throw std::runtime_error("Cannot create task TASK_UPF_SBI");
  }
  // Generate UPF profile
  generate_upf_profile();

  // Register to NRF if needed
  if (upf_cfg.register_nrf) register_to_nrf();
}

//-----------------------------------------------------------------------------------------------------
bool upf_sbi::send_update_nf_instance(
    const std::string& url, const nlohmann::json& data) {
  Logger::upf_app().info("Send NF Update to NRF");

  std::string body = data.dump();
  Logger::upf_app().debug("Send NF Update to NRF (Msg body %s)", body.c_str());
  Logger::upf_app().debug("Send NF Update to NRF (NRF URL %s)", url.c_str());

  oai::sba::sbi_http_request http_request =
      http_client_inst_->prepare_json_request(url, body);
  auto http_response = send_with_policy(
      oai::sba::nrf_call_kind::heartbeat, oai::common::sbi::method_e::PATCH,
      http_request);

  if ((http_response.status_code == oai::common::sbi::http_status_code::OK) or
      (http_response.status_code ==
       oai::common::sbi::http_status_code::NO_CONTENT)) {
    Logger::upf_app().info("Got successful response from NRF");
    return true;
  } else {
    Logger::upf_app().warn("Could not get response from NRF");
    return false;
  }

  return false;
}

//---------------------------------------------------------------------------------------------
void upf_sbi::generate_upf_profile() {
  upf_profile = {};
  // TODO: remove hardcoded values
  upf_profile.set_nf_instance_id(nf_instance_id);
  upf_profile.set_nf_instance_name("OAI-UPF");
  upf_profile.set_nf_type("UPF");
  upf_profile.set_nf_status("REGISTERED");
  upf_profile.set_nf_heartBeat_timer(50);
  upf_profile.set_nf_priority(1);
  upf_profile.set_nf_capacity(100);
  upf_profile.set_fqdn(upf_cfg.fqdn);
  upf_profile.add_nf_ipv4_addresses(upf_cfg.n4.addr4);  // N4's Addr
  // Get NSSAI from conf file
  for (auto s : upf_cfg.upf_info.snssai_upf_info_list) {
    upf_profile.add_snssai(s.snssai);
  }

  // Get UPF Info from conf file
  upf_profile.set_upf_info(upf_cfg.upf_info);
  // Display the profile
  upf_profile.display();
}

//---------------------------------------------------------------------------------------------
bool upf_sbi::register_to_nrf() {
  nlohmann::json json_data = {};
  upf_profile.to_json(json_data);
  oai::common::sbi::nf_addr_t nrf_addr = {};
  nrf_addr.ipv4_addr                   = upf_cfg.nrf_addr.get_addr4();
  nrf_addr.port                        = upf_cfg.nrf_addr.get_port();
  nrf_addr.api_version                 = upf_cfg.nrf_addr.get_api_version();
  nrf_addr.uri_root                    = upf_cfg.nrf_addr.get_url();
  return oai::sba::nf_service::register_to_nrf(nrf_addr, json_data);
}

//---------------------------------------------------------------------------------------------
bool upf_sbi::deregister_to_nrf() {
  Logger::upf_app().debug("Send NF De-registration to NRF");
  return oai::sba::nf_service::deregister_to_nrf();
}

//---------------------------------------------------------------------------------------------
void upf_sbi::timer_nrf_heartbeat_timeout(
    timer_id_t timer_id, uint64_t arg2_user) {
  Logger::upf_app().debug("Send Heartbeat to NRF");

  patch_item_t patch_item = {};
  //{"op":"replace","path":"/nfStatus", "value": "REGISTERED"}
  patch_item.op    = "replace";
  patch_item.path  = "/nfStatus";
  patch_item.value = "REGISTERED";

  nlohmann::json json_data = nlohmann::json::array();
  nlohmann::json item      = patch_item.to_json();
  json_data.push_back(item);

  std::string nrf_api_root = {};
  get_nrf_api_root(nrf_api_root);

  if (send_update_nf_instance(
          nrf_api_root + NNRF_NF_REGISTER_URL + nf_instance_id, json_data)) {
    Logger::upf_app().debug(
        "Set a timer to the next Heart-beat (%d)",
        upf_profile.get_nf_heartBeat_timer());
    timer_nrf_heartbeat = itti_inst->timer_setup(
        upf_profile.get_nf_heartBeat_timer(), 0, TASK_UPF_SBI,
        TASK_UPF_SBI_TIMEOUT_NRF_HEARTBEAT,
        0);  // TODO arg2_user
  } else {
    // Try to register again
    register_to_nrf();
  }
}

//---------------------------------------------------------------------------------------------
void upf_sbi::timer_nrf_deregistration(
    timer_id_t timer_id, uint64_t arg2_user) {
  // timer_id and arg2_user unused?
  deregister_to_nrf();
}

//---------------------------------------------------------------------------------------------
void upf_sbi::timer_nrf_registration(timer_id_t timer_id, uint64_t arg2_user) {
  // timer_id and arg2_user unused?
  register_to_nrf();
}

//---------------------------------------------------------------------------------------------
void upf_sbi::get_nrf_api_root(std::string& api_root) const {
  api_root = std::string(upf_cfg.nrf_addr.get_url()) + NNRF_NFM_BASE +
             upf_cfg.nrf_addr.get_api_version();
}

//---------------------------------------------------------------------------------------------
bool upf_sbi::nrf_registration_enabled() const {
  return upf_cfg.register_nrf;
}

//---------------------------------------------------------------------------------------------
uint64_t upf_sbi::nrf_registration_retry_seconds() const {
  return nrf_retry_interval;
}

//---------------------------------------------------------------------------------------------
bool upf_sbi::registration_succeeded(
    const oai::sba::sbi_http_response& response) const {
  return response.status_code == oai::common::sbi::http_status_code::OK or
         response.status_code == oai::common::sbi::http_status_code::CREATED;
}

//---------------------------------------------------------------------------------------------
void upf_sbi::on_registration_outcome(
    bool success, const oai::sba::sbi_http_response& response) {
  if (success) {
    json response_data = {};
    try {
      response_data = json::parse(response.body);
    } catch (const json::exception&) {
      Logger::upf_app().warn("Could not parse JSON from the NRF response");
    }
    Logger::upf_app().info(
        "Response from NRF, JSON data: \n %s", response_data.dump().c_str());
    upf_profile.from_json(response_data);
    Logger::upf_app().debug("Updated UPF profile");
    upf_profile.display();
    timer_nrf_heartbeat = itti_inst->timer_setup(
        upf_profile.get_nf_heartBeat_timer(), 0, TASK_UPF_SBI,
        TASK_UPF_SBI_TIMEOUT_NRF_HEARTBEAT, 0);
    Logger::upf_app().startup("Started");
    return;
  }

  Logger::upf_app().debug(
      "Set a timer to the next NRF registration try (%d)", nrf_retry_interval);
  timer_nrf_retry = itti_inst->timer_setup(
      nrf_retry_interval, 0, TASK_UPF_SBI,
      TASK_UPF_SBI_TIMEOUT_NRF_REGISTRATION, 0);
}
