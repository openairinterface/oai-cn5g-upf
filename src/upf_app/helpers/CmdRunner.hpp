#ifndef CMDRUNNER_HPP
#define CMDRUNNER_HPP

#include <string>

class CmdRunner {
 public:
  // CmdRunner();

  // Function to execute a shell command and return the output
  static std::string exec(const std::string& cmd);
};

#endif  // CMDRUNNER_HPP