/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __SESSIONPROGRAMS_H__
#define __SESSIONPROGRAMS_H__

#include <memory>
#include <pfcp_session_lookup_xdp_user.h>
#include <unistd.h>
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
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram);
  virtual ~SessionPrograms();
  std::shared_ptr<PFCP_Session_LookupProgram> getPFCPProgram() const;

  pdn_type_e getPdnType() const;

 private:
  std::shared_ptr<PFCP_Session_LookupProgram> mpPFCP_Session_LookupProgram;
  pdn_type_e mPdnType;
};

#endif  // __SESSIONPROGRAMS_H__
