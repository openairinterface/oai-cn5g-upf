/*
 * Copyright (c) 2019 EURECOM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "async_shell_cmd.hpp"
#include "common_defs.h"
#include "http_client.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "options.hpp"
#include "pfcp_switch.hpp"
#include "pid_file.hpp"
#include "upf_app.hpp"
#include "upf_config.hpp"
#include "upf_config_yaml.hpp"
#include "sbi_helper.hpp"

#include <boost/asio.hpp>
#include <iostream>
#include <algorithm>
#include <thread>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>  // get_pid(), pause()
#include <chrono>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>

//#include <RulesUtilitiesImpl.h>
#include <SessionManager.h>
#include <SessionProgramManager.h>
#include <UserPlaneComponent.h>

using namespace oai::upf::app;
using namespace oai::config;
using namespace util;

itti_mw* itti_inst                    = nullptr;
async_shell_cmd* async_shell_cmd_inst = nullptr;
pfcp_switch* pfcp_switch_inst         = nullptr;
upf_app* upf_app_inst                 = nullptr;
upf_config upf_cfg;
boost::asio::io_service io_service;
bool single_teardown_call;

#ifndef N3_IF_NAME
#define N3_IF_NAME upf_cfg.n3.if_name
#endif  // N3_IF_NAME

#ifndef N6_IF_NAME
#define N6_IF_NAME upf_cfg.n6.if_name
#endif  // N6_IF_NAME

#ifndef HTB_SCHEDULER
#define HTB_SCHEDULER "htb"
#endif  // HTB_SCHEDULER

std::unique_ptr<upf_config_yaml> upf_cfg_yaml            = nullptr;
std::shared_ptr<oai::http::http_client> http_client_inst = nullptr;
//------------------------------------------------------------------------------
void my_app_signal_handler(int s) {
  auto shutdown_start = std::chrono::system_clock::now();
  if (single_teardown_call) {
    return;
  }
  single_teardown_call = true;
  // Setting log level arbitrarly to debug to show the whole
  // shutdown procedure in the logs even in case of off-logging
  Logger::set_level(spdlog::level::debug);
  Logger::system().info("Caught signal %d", s);

  // Stop on-going tasks
  if (upf_app_inst) {
    upf_app_inst->stop();
  }
  itti_inst->send_terminate_msg(TASK_UPF_APP);
  itti_inst->wait_tasks_end();

  Logger::system().info("Freeing Allocated memory...");

  if (async_shell_cmd_inst) {
    delete async_shell_cmd_inst;
    async_shell_cmd_inst = nullptr;
    Logger::system().debug("Async Shell CMD memory done.");
  }

  if (upf_app_inst) {
    delete upf_app_inst;
    upf_app_inst = nullptr;
    Logger::system().debug("UPF APP memory done.");
  }

  if (itti_inst) {
    delete itti_inst;
    itti_inst = nullptr;
    Logger::system().debug("ITTI memory done.");
  }

  Logger::system().info("Freeing Allocated memory done.");
  auto elapsed = std::chrono::system_clock::now() - shutdown_start;
  auto ms_diff = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
  Logger::system().info("Bye. Shutdown Procedure took %d ms", ms_diff.count());
  exit(0);
}

//------------------------------------------------------------------------------
void setup_bpf() {
  // std::shared_ptr<RulesUtilities> mpRulesFactory;
  // mpRulesFactory = std::make_shared<RulesUtilitiesImpl>();

  std::string sGTPInterface = N3_IF_NAME;
  std::string sUDPInterface = N6_IF_NAME;
  Logger::upf_app().info("GTP interface: %s", sGTPInterface.c_str());
  Logger::upf_app().info("UDP interface: %s", sUDPInterface.c_str());

  UserPlaneComponent::getInstance().setup(sGTPInterface, sUDPInterface);
}

//------------------------------------------------------------------------------
int main(int argc, char** argv) {
  // Command line options
  if (!Options::parse(argc, argv)) {
    std::cout << "Options::parse() failed" << std::endl;
    return 1;
  }

  // Logger
  Logger::init("upf", Options::getlogStdout(), Options::getlogRotFilelog());

  Logger::upf_app().startup("Options parsed");

  std::signal(SIGTERM, my_app_signal_handler);
  std::signal(SIGINT, my_app_signal_handler);
  single_teardown_call = false;

  // Config
  std::string conf_file_name = Options::getlibconfigConfig();
  Logger::upf_app().debug("Parsing the configuration file, file type YAML.");
  upf_cfg_yaml = std::make_unique<upf_config_yaml>(
      conf_file_name, Options::getlogStdout(), Options::getlogRotFilelog());
  if (!upf_cfg_yaml->init()) {
    Logger::upf_app().error("Reading the configuration failed. Exiting.");
    return 1;
  }
  upf_cfg_yaml->pre_process();
  // Convert from YAML to internal structure
  upf_cfg_yaml->to_upf_config(upf_cfg);
  upf_cfg_yaml->display();

  // HTTP Client
  // HTTP Client
  http_client_inst = oai::http::http_client::create_instance(
      Logger::upf_app(), upf_cfg.http_request_timeout, upf_cfg.sbi.if_name,
      upf_cfg.http_version);

  // Inter task Interface
  itti_inst = new itti_mw();
  itti_inst->start(upf_cfg.itti.itti_timer_sched_params);

  // system command
  async_shell_cmd_inst =
      new async_shell_cmd(upf_cfg.itti.async_cmd_sched_params);

  // PGW application layer
  upf_app_inst = new upf_app(Options::getlibconfigConfig());

  // PID file
  // Currently hard-coded value. TODO: add as config option.
  std::string pid_file_name =
      oai::utils::get_exe_absolute_path("/var/run", upf_cfg.instance);
  if (!oai::utils::is_pid_file_lock_success(pid_file_name.c_str())) {
    Logger::upf_app().error("Lock PID file %s failed\n", pid_file_name.c_str());
    exit(-EDEADLK);
  }

  FILE* fp             = NULL;
  std::string filename = fmt::format("/tmp/upf_{}.status", getpid());
  fp                   = fopen(filename.c_str(), "w+");
  fprintf(fp, "STARTED\n");
  fflush(fp);
  fclose(fp);

  if (upf_cfg.enable_bpf_datapath) {
    setup_bpf();
  }
  // once all udp servers initialized
  io_service.run();

  pause();
  return 0;
}
