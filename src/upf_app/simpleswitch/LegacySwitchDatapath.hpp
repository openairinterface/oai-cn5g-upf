/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef LEGACY_SWITCH_DATAPATH_HPP_
#define LEGACY_SWITCH_DATAPATH_HPP_

#include "pfcp_switch.hpp"
#include "session/IUpfDatapath.h"

namespace oai {
namespace upf {
namespace app {

/**
 * @class LegacySwitchDatapath
 * @brief IUpfDatapath adaptor over pfcp_switch — the simple-switch and eBPF
 *        flavours as they exist today.
 *
 * Both of those flavours still share one pfcp_switch: it holds the session
 * tables and, for eBPF, forwards rules to SessionManager. This adaptor exists
 * so upf_app talks to every flavour through the same interface. Splitting
 * simple-switch and eBPF into two proper implementations is the follow-up
 * refactor; nothing outside this class needs to change when that happens.
 */
class LegacySwitchDatapath : public IUpfDatapath {
 public:
  explicit LegacySwitchDatapath(pfcp_switch* pfcp_switch_instance)
      : switch_(pfcp_switch_instance) {}

  void HandleSessionEstablishment(
      std::shared_ptr<itti_n4_session_establishment_request> request,
      itti_n4_session_establishment_response* response) override {
    switch_->handle_pfcp_session_establishment_request(request, response);
  }

  void HandleSessionModification(
      std::shared_ptr<itti_n4_session_modification_request> request,
      itti_n4_session_modification_response* response) override {
    switch_->handle_pfcp_session_modification_request(request, response);
  }

  void HandleSessionDeletion(
      std::shared_ptr<itti_n4_session_deletion_request> request,
      itti_n4_session_deletion_response* response) override {
    switch_->handle_pfcp_session_deletion_request(request, response);
  }

  void RemoveSession(const pfcp::fseid_t& cp_fseid) override {
    switch_->remove_pfcp_session(cp_fseid);
  }

 private:
  pfcp_switch* switch_;  ///< Not owned; lifetime managed by upf_app.
};

}  // namespace app
}  // namespace upf
}  // namespace oai

#endif  // LEGACY_SWITCH_DATAPATH_HPP_
