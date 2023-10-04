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
#include "itti.hpp"
#include "logger.hpp"
#include "options.hpp"
#include "pfcp_switch.hpp"
#include "pid_file.hpp"
#include "upf_app.hpp"
#include "upf_config.hpp"
#include "upf_config_yaml.hpp"
#include "upf_nrf.hpp"

#include <boost/asio.hpp>
#include <iostream>
#include <algorithm>
#include <thread>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>  // get_pid(), pause()
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>

#include <RulesUtilitiesImpl.h>
#include <SessionManager.h>
#include <SessionProgramManager.h>
#include <UserPlaneComponent.h>

// #include "upf_config.hpp"
//  extern oai::config::upf_config upf_cfg;
using namespace oai::upf::app;
using namespace oai::config;
using namespace util;
using namespace std;

// static std::shared_ptr<SessionManager> spSessionManager;

itti_mw* itti_inst                    = nullptr;
async_shell_cmd* async_shell_cmd_inst = nullptr;
pfcp_switch* pfcp_switch_inst         = nullptr;
upf_app* upf_app_inst                 = nullptr;
upf_config upf_cfg;
boost::asio::io_service io_service;
// TODO These global variables are ugly :| -> refactor together with nrf client
extern upf_nrf* upf_nrf_inst;

#ifndef N3_IF_NAME
#define N3_IF_NAME upf_cfg.n3.if_name
#endif

#ifndef N6_IF_NAME
#define N6_IF_NAME upf_cfg.n6.if_name
#endif

std::unique_ptr<upf_config_yaml> upf_cfg_yaml = nullptr;

//------------------------------------------------------------------------------
void my_app_signal_handler(int s) {
  std::cout << "Caught signal " << s << std::endl;
  Logger::system().startup("exiting");
  if (upf_nrf_inst) {
    upf_nrf_inst->deregister_to_nrf();
  }
  itti_inst->send_terminate_msg(TASK_UPF_APP);
  itti_inst->wait_tasks_end();
  std::cout << "Freeing Allocated memory..." << std::endl;
  if (async_shell_cmd_inst) delete async_shell_cmd_inst;
  async_shell_cmd_inst = nullptr;
  std::cout << "Async Shell CMD memory done." << std::endl;
  if (itti_inst) delete itti_inst;
  itti_inst = nullptr;
  std::cout << "ITTI memory done." << std::endl;
  if (upf_app_inst) delete upf_app_inst;
  upf_app_inst = nullptr;
  std::cout << "UPF APP memory done." << std::endl;
  std::cout << "Freeing Allocated memory done" << std::endl;
  exit(0);
}
//------------------------------------------------------------------------------
// We are doing a check to see if an existing process already runs this program.
// We have seen that running at least twice this program in a container may lead
// to the container host to crash.
int my_check_redundant_process(char* exec_name) {
  FILE* fp;
  char* cmd = new char[200];
  std::vector<std::string> words;
  int result     = 0;
  size_t retSize = 0;

  // Retrieving only the executable name
  boost::split(words, exec_name, boost::is_any_of("/"));
  memset(cmd, 0, 200);
  sprintf(
      cmd, "ps aux | grep -v grep | grep -v nohup | grep -c %s || true",
      words[words.size() - 1].c_str());
  fp = popen(cmd, "r");

  // clearing the buffer
  memset(cmd, 0, 200);
  retSize = fread(cmd, 1, 200, fp);
  fclose(fp);

  // if something wrong, then we don't know
  if (retSize == 0) {
    delete[] cmd;
    return 10;
  }

  result = atoi(cmd);
  delete[] cmd;
  return result;
}
//------------------------------------------------------------------------------
void setup_bpf() {
  std::shared_ptr<RulesUtilities> mpRulesFactory;
  mpRulesFactory = std::make_shared<RulesUtilitiesImpl>();

  string sGTPInterface = N3_IF_NAME;
  string sUDPInterface = N6_IF_NAME;
  Logger::upf_app().info("GTP interface: %s", sGTPInterface.c_str());
  Logger::upf_app().info("UDP interface: %s", sUDPInterface.c_str());
  UserPlaneComponent::getInstance().setup(
      mpRulesFactory, sGTPInterface, sUDPInterface);
  // spSessionManager = UserPlaneComponent::getInstance().getSessionManager();
}
//------------------------------------------------------------------------------
int main(int argc, char** argv) {
  // Checking if another instance of UPF is running
  // int nb_processes = my_check_redundant_process(argv[0]);
  // if (nb_processes > 1) {
  //   std::cout << "An instance of " << argv[0] << " is maybe already called!"
  //             << std::endl;
  //   std::cout << "  " << nb_processes << " were detected" << std::endl;
  //   return -1;
  // }

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

  // Config
  std::string conf_file_name = Options::getlibconfigConfig();
  std::string file_ext       = ".conf";
  if (conf_file_name.find(file_ext) != std::string::npos) {
    Logger::upf_app().debug("Parsing the configuration file, file type CONF.");
    upf_cfg.load(conf_file_name);
    Logger::set_level(upf_cfg.log_level);
    upf_cfg.display();
  } else {
    // By default, considering the config file as yaml
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
  }

  // upf_cfg.load(Options::getlibconfigConfig());
  // upf_cfg.display();
  // Logger::set_level(upf_cfg.log_level);

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
  string pid_file_name = get_exe_absolute_path("/var/run", upf_cfg.instance);
  if (!is_pid_file_lock_success(pid_file_name.c_str())) {
    Logger::upf_app().error("Lock PID file %s failed\n", pid_file_name.c_str());
    exit(-EDEADLK);
  }

  FILE* fp             = NULL;
  std::string filename = fmt::format("/tmp/upf_{}.status", getpid());
  fp                   = fopen(filename.c_str(), "w+");
  fprintf(fp, "STARTED\n");
  fflush(fp);
  fclose(fp);

  if (upf_cfg.enable_bpf_datapath) setup_bpf();
  // once all udp servers initialized
  io_service.run();

  pause();
  return 0;
}
