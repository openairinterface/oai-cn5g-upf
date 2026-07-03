/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pfcp_qer.hpp"

#include "pfcp_switch.hpp"
#include "simple_switch.hpp"
#include "upf_config.hpp"

using namespace pfcp;

//------------------------------------------------------------------------------
// update() — 3GPP TS 29.244 V17.10.0 Table 7.5.4.5-1 (Update QER).
// Each IE is overwritten only when present in the Update QER message.

//------------------------------------------------------------------------------
bool pfcp_qer::update(
    const pfcp::update_qer& updated_qer, uint8_t& cause_value) {
  // 3GPP TS 29.244 V17.10.0 Table 7.5.4.5-1 — Update QER IEs
  if (updated_qer.get(qer_id.second))
    qer_id.first = true;  // §8.2.75 — Sxb+Sxc+N4+N4mb
  if (updated_qer.get(qer_correlation_id.second))
    qer_correlation_id.first = true;  // §8.2.10 — Sxb+N4
  if (updated_qer.get(gate_status.second))
    gate_status.first = true;  // §8.2.7  — Sxb+Sxc+N4+N4mb
  if (updated_qer.get(maximum_bitrate.second))
    maximum_bitrate.first = true;  // §8.2.8  — Sxb+Sxc+N4+N4mb
  if (updated_qer.get(guaranteed_bitrate.second))
    guaranteed_bitrate.first = true;  // §8.2.9  — Sxb+Sxc+N4+N4mb
  if (updated_qer.get(qos_flow_id.second))
    qos_flow_id.first = true;  // §8.2.89 — N4+N4mb
  if (updated_qer.get(reflective_qos.second))
    reflective_qos.first = true;  // §8.2.88 — N4
  if (updated_qer.get(paging_policy_indicator.second))
    paging_policy_indicator.first = true;  // §8.2.116 — N4
  if (updated_qer.get(averaging_window.second))
    averaging_window.first = true;  // §8.2.115 — N4

  // TODO §8.2.63  — Packet Rate (C, Sxb+N4, Table 7.5.4.5-1)
  //   Excluded from this impl (no N4 enforcement path for packet-rate
  //   policing). Add when needed.
  // TODO §8.2.66  — DL Flow Level Marking (C, Sxb+Sxc, Table 7.5.4.5-1)
  //   Excluded — not applicable to N4. Add if Sxb/Sxc support is needed.
  // TODO §8.2.174 — QER Control Indications (C, Sxb+N4, Table 7.5.4.5-1)
  //   present in pfcp::update_qer but absent from pfcp::create_qer (lib gap).
  //   Add field to pfcp_qer and wire here when lib is updated:
  //     pfcp::qer_control_indications_t qci = {};
  //     if (updated_qer.get(qci)) { qer_control_indications = {true, qci}; }
  // TODO §8.2.216 — QER Indications (C, N4mb only, Table 7.5.4.5-1)
  //   Not in lib at all. Add when lib is updated.

  cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}
