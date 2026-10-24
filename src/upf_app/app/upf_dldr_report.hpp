/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UPF_DLDR_REPORT_HPP_SEEN
#define FILE_UPF_DLDR_REPORT_HPP_SEEN

#include "msg_pfcp.hpp"

namespace oai {
namespace upf {
namespace app {

//------------------------------------------------------------------------------
// 3GPP TS 29.244 V17.10.0 Table 7.5.8.1-1 — PFCP Session Report Request.
// Builds a Downlink Data Report: Report Type IE (§8.2.21) with the DLDR flag
// set, plus a Downlink Data Report IE (Table 7.5.8.2-1) carrying the DL PDR ID
// (§8.2.36) that detected the downlink packet and, when known (qfi >= 0),
// the Downlink Data Service Information (§8.2.27) with its QFI: for 5GC it
// shall be included if the QFI of the DL packet is available (§7.5.8.2).
inline pfcp::pfcp_session_report_request make_dldr_report(
    const pfcp::pdr_id_t& pdr_id, int qfi = -1) {
  pfcp::pfcp_session_report_request h;

  pfcp::report_type_t report_type = {};
  report_type.dldr                = 1;

  pfcp::downlink_data_report dl_data_report;
  dl_data_report.set(pdr_id);
  if (qfi >= 0) {
    pfcp::downlink_data_service_information_t ddsi = {};
    ddsi.qfii                                      = 1;
    ddsi.qfi                                       = static_cast<uint8_t>(qfi);
    dl_data_report.set(ddsi);
  }
  inline pfcp::pfcp_session_report_request make_dldr_report(
      const pfcp::pdr_id_t& pdr_id) {
    pfcp::pfcp_session_report_request h;

    pfcp::report_type_t report_type = {};
    report_type.dldr                = 1;

    pfcp::downlink_data_report dl_data_report;
    dl_data_report.set(pdr_id);

    h.set(report_type);
    h.set(dl_data_report);

    return h;
  }

}  // namespace app
}  // namespace upf
}  // namespace oai

#endif /* FILE_UPF_DLDR_REPORT_HPP_SEEN */
