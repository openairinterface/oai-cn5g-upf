/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DL_DATA_REPORT_HPP_INCLUDED_
#define DL_DATA_REPORT_HPP_INCLUDED_

#include <cstdint>

// UPF-internal bookkeeping for a Downlink Data Report: which local session
// and DL PDR raised it. Not encoded on N4.
struct dl_data_report_origin {
  uint64_t up_seid = 0;
  uint16_t pdr_id  = 0;
};
// Outcome of handing a PFCP Session Report Request to TASK_UPF_N4.
enum class session_report_enqueue_result {
  queued,
  no_peer_address,
  itti_refused
};

#endif /* DL_DATA_REPORT_HPP_INCLUDED_ */
