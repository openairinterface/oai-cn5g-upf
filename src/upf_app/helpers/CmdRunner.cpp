#include "CmdRunner.hpp"
#include <array>
#include <memory>
#include <stdexcept>
#include <cstdio>  // For popen and pclose

// CmdRunner::CmdRunner() {}

//------------------------------------------------------------------------
std::string CmdRunner::exec(const std::string& cmd) {
  std::array<char, 256> buffer;
  std::string result;
  std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);

  if (!pipe) {
    throw std::runtime_error("popen() failed!");
  }

  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }

  return result;
}
