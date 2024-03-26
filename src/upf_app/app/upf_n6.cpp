
#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "upf_config.hpp"
#include "upf_n6.hpp"

#include <chrono>
#include <ctime>
#include <stdexcept>

using namespace oai::upf::app;
using namespace oai::config;
using namespace std;

extern itti_mw* itti_inst;
extern upf_config upf_cfg;
extern upf_n6* upf_n6_inst;

//------------------------------------------------------------------------------
upf_n6::upf_n6()
    : raw_s(raw_server(upf_cfg.n6.if_name.c_str())) {
  Logger::upf_n6().info(
      "upf_n6 created listening to %s",
      inet_ntoa(upf_cfg.n6.addr4));

  id = 0;
  raw_s.start_receive(this, upf_cfg.n6.thread_rd_sched_params);
  Logger::upf_n6().startup("Started");
}

//------------------------------------------------------------------------------
void upf_n6::handle_receive(
    const char* recv_buffer, const std::size_t bytes_transferred) {

    for (size_t i = 0; i < bytes_transferred; ++i) {
        std::cout << std::hex << static_cast<int>(recv_buffer[i]) << " ";
    }
    std::cout << std::endl;
}