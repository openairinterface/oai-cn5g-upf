/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pfcp_bar.hpp"

using namespace pfcp;

// =============================================================================
// Update BAR — Session Modification Request path
// 3GPP TS 29.244 V17.10.0 Table 7.5.4.11-1
// =============================================================================

//------------------------------------------------------------------------------
// update() — Session Modification Request
//
// IEs present in update_bar_within_pfcp_session_modification_request (lib):
//   - downlink_data_notification_delay  §8.2.28  Sxa + N4
//   - suggested_buffering_packets_count §8.2.100 Sxb + Sxc + N4
//
// IEs NOT yet in the lib (TODO — lib gap, msg_pfcp.hpp not updated to V17.10):
//   - dl_buffering_duration             §8.2.29  Sxa + N4
//   - dl_buffering_suggested_packet_count §8.2.30 Sxa + N4
//
// Direct pair assignment is not possible: the stored types differ from the
// PFCP wire types (bar_dl_delay_t ≠ downlink_data_notification_delay_t,
// bar_buffering_count_t ≠ suggested_buffering_packets_count_t). Each field
// must be converted scalar-by-scalar.

//------------------------------------------------------------------------------
bool pfcp_bar::update(
    const pfcp::update_bar_within_pfcp_session_modification_request& u,
    uint8_t& cause_value) {
  // §8.2.28 — Downlink Data Notification Delay (Sxa + N4, Table 7.5.4.11-1)
  pfcp::downlink_data_notification_delay_t ddn = {};
  if (u.get(ddn)) {
    downlink_data_notification_delay.first              = true;
    downlink_data_notification_delay.second.delay_value = ddn.delay;
  }

  // §8.2.100 — Suggested Buffering Packets Count (Sxb+Sxc+N4, Table 7.5.4.11-1,
  // UDBC feature)
  pfcp::suggested_buffering_packets_count_t sbc = {};
  if (u.get(sbc)) {
    suggested_buffering_packets_count.first = true;
    suggested_buffering_packets_count.second.packet_count =
        sbc.packets_count_value;
  }

  // TODO §8.2.29 — DL Buffering Duration (Sxa+N4, Table 7.5.4.11-1)
  //   update_bar_within_pfcp_session_modification_request does not carry
  //   dl_buffering_duration yet (lib gap — msg_pfcp.hpp not updated to V17.10).
  //   Add when the lib exposes:
  //     pfcp::dl_buffering_duration_t dbd = {};
  //     if (u.get(dbd)) {
  //       dl_buffering_duration.first              = true;
  //       dl_buffering_duration.second.timer_value = dbd.timer_value;
  //     }

  // TODO §8.2.30 — DL Buffering Suggested Packet Count (Sxa+N4,
  // Table 7.5.4.11-1)
  //   Same lib gap. Add when the lib exposes:
  //     pfcp::dl_buffering_suggested_packet_count_t dbspc = {};
  //     if (u.get(dbspc)) {
  //       dl_buffering_suggested_packet_count.first = true;
  //       dl_buffering_suggested_packet_count.second.suggested_packet_count =
  //           dbspc.packet_count;
  //     }

  cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}

// =============================================================================
// Update BAR — Session Report Response path
// 3GPP TS 29.244 V17.10.0 Table 7.5.9.2-1
// =============================================================================

//------------------------------------------------------------------------------
// update() — Session Report Response
//
// Richer than the Modification Request path: this lib type carries all five
// BAR IEs. DL Buffering Duration and DL Buffering Suggested Packet Count are
// stored in pfcp_bar for session state tracking but are NOT yet forwarded to
// the kernel BPF map (struct pfcp_bar in pfcp_bar.h is missing these fields).
// See TODO in pfcp_bar.hpp field declarations and in ConvertBar().

//------------------------------------------------------------------------------
bool pfcp_bar::update(
    const pfcp::update_bar_within_pfcp_session_report_response& u,
    uint8_t& cause_value) {
  // §8.2.28 — Downlink Data Notification Delay (Sxa+N4, Table 7.5.9.2-1)
  pfcp::downlink_data_notification_delay_t ddn = {};
  if (u.get(ddn)) {
    downlink_data_notification_delay.first              = true;
    downlink_data_notification_delay.second.delay_value = ddn.delay;
  }

  // §8.2.29 — DL Buffering Duration (Sxa+N4, Table 7.5.9.2-1)
  // GPRS Timer encoding (3GPP TS 24.008 §10.5.7.4a).
  pfcp::dl_buffering_duration_t dbd = {};
  if (u.get(dbd)) {
    dl_buffering_duration.first              = true;
    dl_buffering_duration.second.timer_value = dbd.timer_value;
  }

  // §8.2.30 — DL Buffering Suggested Packet Count (Sxa+N4, Table 7.5.9.2-1)
  pfcp::dl_buffering_suggested_packet_count_t dbspc = {};
  if (u.get(dbspc)) {
    dl_buffering_suggested_packet_count.first = true;
    dl_buffering_suggested_packet_count.second.suggested_packet_count =
        dbspc.packet_count;
  }

  // §8.2.100 — Suggested Buffering Packets Count (Sxb+Sxc+N4, Table 7.5.9.2-1,
  // UDBC feature)
  pfcp::suggested_buffering_packets_count_t sbc = {};
  if (u.get(sbc)) {
    suggested_buffering_packets_count.first = true;
    suggested_buffering_packets_count.second.packet_count =
        sbc.packets_count_value;
  }

  cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}
