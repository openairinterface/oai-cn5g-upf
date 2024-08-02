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

/*! \file upf_nrf.cpp
 \brief
 \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
 \company Eurecom
 \date 2021
 \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#include "upf_nrf.hpp"

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
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
extern upf_nrf* upf_nrf_inst;
extern upf_config upf_cfg;
extern std::shared_ptr<oai::http::http_client> http_client_inst;
void upf_nrf_task(void*);

//------------------------------------------------------------------------------
void upf_nrf_task(void* args_p) {
  const task_id_t task_id = TASK_UPF_NRF;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto* msg                            = shared_msg.get();
    switch (msg->msg_type) {
      case TIME_OUT:
        if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
          Logger::upf_app().info("TIME-OUT event timer id %d", to->timer_id);
          switch (to->arg1_user) {
            case TASK_UPF_NRF_TIMEOUT_NRF_HEARTBEAT:
              upf_nrf_inst->timer_nrf_heartbeat_timeout(
                  to->timer_id, to->arg2_user);
              break;
            case TASK_UPF_NRF_TIMEOUT_NRF_DEREGISTRATION:
              upf_nrf_inst->timer_nrf_deregistration(
                  to->timer_id, to->arg2_user);
              break;
            case TASK_UPF_NRF_TIMEOUT_NRF_REGISTRATION:
              upf_nrf_inst->timer_nrf_registration(to->timer_id, to->arg2_user);
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
upf_nrf::upf_nrf() {
  Logger::upf_app().startup("Starting...");

  upf_profile         = {};
  upf_instance_id     = {};
  timer_nrf_heartbeat = {};
  timer_nrf_retry     = {};

  if (itti_inst->create_task(TASK_UPF_NRF, upf_nrf_task, nullptr)) {
    Logger::upf_app().error("Cannot create task TASK_UPF_NRF");
    throw std::runtime_error("Cannot create task TASK_UPF_NRF");
  }
  // Generate UPF profile
  generate_upf_profile();

  // Register to NRF if needed
  if (upf_cfg.register_nrf) register_to_nrf();
}

//-----------------------------------------------------------------------------------------------------
bool upf_nrf::send_register_nf_instance(const std::string& url) {
  Logger::upf_app().info("Send NF Instance Registration to NRF");

  nlohmann::json json_data = {};
  upf_profile.to_json(json_data);

  Logger::upf_app().debug(
      "Send NF Instance Registration to NRF (NRF URL %s)", url.c_str());

  std::string body = json_data.dump();
  Logger::upf_app().debug(
      "Send NF Instance Registration to NRF, msg body: \n %s", body.c_str());

  std::string response = {};

  oai::http::request http_request =
      http_client_inst->prepare_json_request(url, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PUT, http_request);
  response = http_response.body;

  if ((http_response.status_code == oai::common::sbi::http_status_code::OK) or
      (http_response.status_code ==
       oai::common::sbi::http_status_code::CREATED)) {
    json response_data = {};
    try {
      response_data = json::parse(response.c_str());
    } catch (json::exception& e) {
      Logger::upf_app().warn("Could not parse JSON from the NRF response");
    }
    Logger::upf_app().info(
        "Response from NRF, JSON data: \n %s", response_data.dump().c_str());

    // Update NF profile
    upf_profile.from_json(response_data);
    Logger::upf_app().debug("Updated UPF profile");
    upf_profile.display();

    // Set Heartbeat timer timeout
    timer_nrf_heartbeat = itti_inst->timer_setup(
        upf_profile.get_nf_heartBeat_timer(), 0, TASK_UPF_NRF,
        TASK_UPF_NRF_TIMEOUT_NRF_HEARTBEAT,
        0);  // TODO arg2_user
    return true;
  } else {
    Logger::upf_app().warn("Could not get response from NRF");
    return false;
  }
}

//-----------------------------------------------------------------------------------------------------
bool upf_nrf::send_update_nf_instance(
    const std::string& url, const nlohmann::json& data) {
  Logger::upf_app().info("Send NF Update to NRF");

  std::string body = data.dump();
  Logger::upf_app().debug("Send NF Update to NRF (Msg body %s)", body.c_str());
  Logger::upf_app().debug("Send NF Update to NRF (NRF URL %s)", url.c_str());

  oai::http::request http_request =
      http_client_inst->prepare_json_request(url, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PATCH, http_request);

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

//-----------------------------------------------------------------------------------------------------
void upf_nrf::send_deregister_nf_instance(const std::string& url) {
  Logger::upf_app().info("Send NF De-register to NRF");

  Logger::upf_app().debug(
      "Send NF De-register to NRF (NRF URL %s)", url.c_str());

  oai::http::request http_request = http_client_inst->prepare_json_request(url);
  auto http_response              = http_client_inst->send_http_request(
      oai::common::sbi::method_e::DELETE, http_request);

  if (http_response.status_code ==
      oai::common::sbi::http_status_code::NO_CONTENT) {
    Logger::upf_app().info("Got successful response from NRF de-registration");
  } else {
    Logger::upf_app().warn("Could not get response from NRF");
  }
}

//---------------------------------------------------------------------------------------------
void upf_nrf::generate_upf_profile() {
  // generate UUID
  generate_uuid();
  upf_profile = {};
  // TODO: remove hardcoded values
  upf_profile.set_nf_instance_id(upf_instance_id);
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
void upf_nrf::register_to_nrf() {
  std::string nrf_api_root = {};
  get_nrf_api_root(nrf_api_root);
  if (send_register_nf_instance(
          nrf_api_root + NNRF_NF_REGISTER_URL + upf_instance_id)) {
    Logger::upf_app().startup("Started");
  } else {
    Logger::upf_app().debug(
        "Set a timer to the next NRF registration try (%d)",
        nrf_retry_interval);
    timer_nrf_retry = itti_inst->timer_setup(
        nrf_retry_interval, 0, TASK_UPF_NRF,  // TODO TIMER VARIABLE
        TASK_UPF_NRF_TIMEOUT_NRF_REGISTRATION,
        0);  // TODO arg2_user
  }
}

//---------------------------------------------------------------------------------------------
void upf_nrf::deregister_to_nrf() {
  if (!upf_cfg.register_nrf) return;
  Logger::upf_app().debug("Send NF De-registration to NRF");

  std::string nrf_api_root = {};
  get_nrf_api_root(nrf_api_root);

  send_deregister_nf_instance(
      nrf_api_root + NNRF_NF_REGISTER_URL + upf_instance_id);
}

//------------------------------------------------------------------------------
void upf_nrf::generate_uuid() {
  upf_instance_id = to_string(boost::uuids::random_generator()());
}

//---------------------------------------------------------------------------------------------
void upf_nrf::timer_nrf_heartbeat_timeout(
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
          nrf_api_root + NNRF_NF_REGISTER_URL + upf_instance_id, json_data)) {
    Logger::upf_app().debug(
        "Set a timer to the next Heart-beat (%d)",
        upf_profile.get_nf_heartBeat_timer());
    timer_nrf_heartbeat = itti_inst->timer_setup(
        upf_profile.get_nf_heartBeat_timer(), 0, TASK_UPF_NRF,
        TASK_UPF_NRF_TIMEOUT_NRF_HEARTBEAT,
        0);  // TODO arg2_user
  } else {
    // Try to register again
    register_to_nrf();
  }
}

//---------------------------------------------------------------------------------------------
void upf_nrf::timer_nrf_deregistration(
    timer_id_t timer_id, uint64_t arg2_user) {
  // timer_id and arg2_user unused?
  deregister_to_nrf();
}

//---------------------------------------------------------------------------------------------
void upf_nrf::timer_nrf_registration(timer_id_t timer_id, uint64_t arg2_user) {
  // timer_id and arg2_user unused?
  register_to_nrf();
}

//---------------------------------------------------------------------------------------------
void upf_nrf::get_nrf_api_root(std::string& api_root) {
  api_root = std::string(upf_cfg.nrf_addr.get_url()) + NNRF_NFM_BASE +
             upf_cfg.nrf_addr.get_api_version();
}
