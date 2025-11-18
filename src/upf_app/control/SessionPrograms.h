#ifndef __SESSIONPROGRAMS_H__
#define __SESSIONPROGRAMS_H__

#include <memory>
#include <upf_xdp_user.h>
#include <unistd.h>

/**
 * @brief This class represents the Data-Path path. It stores the program
 * related to a PFCP session. For each session, there might be a QERProgram. The
 * FARProgram is mandatory.
 *
 */
class SessionPrograms {
 public:
  SessionPrograms(std::shared_ptr<UPF_XDPProgram> pUPF_XDPProgram);
  virtual ~SessionPrograms();
  std::shared_ptr<UPF_XDPProgram> getPFCPProgram() const;

 private:
  std::shared_ptr<UPF_XDPProgram> mpUPF_XDPProgram;
};

#endif  // __SESSIONPROGRAMS_H__
