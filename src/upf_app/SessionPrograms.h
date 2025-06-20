#ifndef __SESSIONPROGRAMS_H__
#define __SESSIONPROGRAMS_H__

#include <memory>
#include <pfcp_session_lookup_xdp_user.h>
#include <unistd.h>
#include <next_prog_rule_key.h>
#include "3gpp_29.274.h"

/**
 * @brief This class represents the Data-Path path. It stores the program
 * related to a PFCP session. For each session, there might be a QERProgram. The
 * FARProgram is mandatory.
 *
 */
class SessionPrograms {
 public:
  SessionPrograms(
      struct next_rule_prog_index_key key,
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram);
  virtual ~SessionPrograms();
  struct next_rule_prog_index_key getKey() const;
  std::shared_ptr<PFCP_Session_LookupProgram> getPFCPProgram() const;

  pdn_type_e getPdnType() const;
  struct next_rule_eth_prog_index_key getKeyEth() const;

 private:
  std::shared_ptr<PFCP_Session_LookupProgram> mpPFCP_Session_LookupProgram;
  struct next_rule_prog_index_key mKey;
  struct next_rule_eth_prog_index_key mKeyEth;
  pdn_type_e mPdnType;
};

#endif  // __SESSIONPROGRAMS_H__
