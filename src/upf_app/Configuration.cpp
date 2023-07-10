/**
 * Auto-generated file. Do not modify this file.
 * Check Configuration.cpp.in.
 */
#include "Configuration.h"
#include <string>
#include "logger.hpp"
#include "upf_config.hpp"

using namespace oai::config;

extern upf_config upf_cfg;

std::string Configuration::sGTPInterface            = upf_cfg.n3.if_name;
std::string Configuration::sUDPInterface            = upf_cfg.n6.if_name;
unsigned char Configuration::sIsSocketBufferEnabled = 0;

Configuration::Configuration(int argc, char** argv) {
  if (argc >= 2) {
    Configuration::sGTPInterface = argv[1];
    Configuration::sUDPInterface = argv[2];
  }

  Logger::upf_app().debug(
      "GTP Inteface %s", Configuration::sGTPInterface.c_str());
  Logger::upf_app().debug(
      "UDPInteface %s", Configuration::sUDPInterface.c_str());
  for (int i = 1; i < argc; ++i) {
    Logger::upf_app().debug("arg %d = %d", i, argv[i]);
  }
}
