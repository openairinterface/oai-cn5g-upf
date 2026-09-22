/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RuleConverter.h"

#include "SdfFilterParser.hpp"
#include "logger.hpp"
#include "pfcp_bar.hpp"
#include "pfcp_far.hpp"
#include "pfcp_mar.hpp"
#include "pfcp_pdr.hpp"
#include "pfcp_qer.hpp"
#include "pfcp_urr.hpp"

namespace rules {

//------------------------------------------------------------------------------
struct pfcp_far ConvertFar(
    std::shared_ptr<pfcp::pfcp_far> far) {
  struct pfcp_far bpf_far = {};

  if (!far) return bpf_far;

  // FAR ID (3GPP TS 29.244 Section 8.2.74)
  bpf_far.far_id.far_id = far->far_id.far_id;

  // Apply Action (3GPP TS 29.244 Section 8.2.26)
  // memcpy(
  //     &bpf_far.apply_action, &far->apply_action, sizeof(struct
  //     apply_action));
  bpf_far.apply_action.drop  = far->apply_action.drop ? 1 : 0;
  bpf_far.apply_action.forw  = far->apply_action.forw ? 1 : 0;
  bpf_far.apply_action.buff  = far->apply_action.buff ? 1 : 0;
  bpf_far.apply_action.nocp  = far->apply_action.nocp ? 1 : 0;
  bpf_far.apply_action.dupl  = far->apply_action.dupl ? 1 : 0;
  bpf_far.apply_action.spare = 0;

  // Forwarding Parameters (3GPP TS 29.244 Section 8.2.74)
  if (far->forwarding_parameters.first) {
    bpf_far.forwarding_parameters.destination_interface.interface_value =
        far->forwarding_parameters.second.destination_interface.second
            .interface_value;

    // Outer Header Creation (3GPP TS 29.244 Section 8.2.74)
    if (far->forwarding_parameters.second.outer_header_creation.first) {
      bpf_far.forwarding_parameters.outer_header_creation.teid =
          far->forwarding_parameters.second.outer_header_creation.second.teid;

      bpf_far.forwarding_parameters.outer_header_creation.port_number =
          far->forwarding_parameters.second.outer_header_creation.second
              .port_number;

      bpf_far.forwarding_parameters.outer_header_creation.description =
          far->forwarding_parameters.second.outer_header_creation.second
              .outer_header_creation_description;

      bpf_far.forwarding_parameters.outer_header_creation.ipv4_address.s_addr =
          far->forwarding_parameters.second.outer_header_creation.second
              .ipv4_address.s_addr;
    }
  }

  return bpf_far;
}

//------------------------------------------------------------------------------
struct pfcp_pdr ConvertPdr(
    std::shared_ptr<pfcp::pfcp_pdr> pdr) {
  struct pfcp_pdr bpf_pdr = {};

  if (!pdr) return bpf_pdr;

  // PDR ID and Precedence (3GPP TS 29.244 Section 8.2.29)
  bpf_pdr.pdr_id.rule_id        = pdr->pdr_id.rule_id;
  bpf_pdr.precedence.precedence = pdr->precedence.second.precedence;

  // Associated rule IDs
  bpf_pdr.far_id.far_id = pdr->far_id.second.far_id;
  bpf_pdr.qer_id.qer_id = pdr->qer_id.second.qer_id;
  bpf_pdr.urr_id        = pdr->urr_id.second.urr_id;

  // PDI (Packet Detection Information)
  if (pdr->pdi.first) {
    // Source Interface (3GPP TS 29.244 Section 8.2.62)
    bpf_pdr.pdi.source_interface.interface_value =
        pdr->pdi.second.source_interface.second.interface_value;

    // F-TEID (3GPP TS 29.244 Section 8.2.3)
    if (pdr->pdi.second.local_fteid.first) {
      bpf_pdr.pdi.fteid.teid = pdr->pdi.second.local_fteid.second.teid;
    }

    // UE IP Address (3GPP TS 29.244 Section 8.2.62)
    if (pdr->pdi.second.ue_ip_address.first) {
      bpf_pdr.pdi.ue_ip_address.ipv4_address.s_addr =
          pdr->pdi.second.ue_ip_address.second.ipv4_address.s_addr;
    }

    // SDF Filter (3GPP TS 29.244 Section 8.2.5)
    if (pdr->pdi.second.sdf_filter.first) {
      bpf_pdr.pdi.sdf_filter.flow_desc_len =
          pdr->pdi.second.sdf_filter.second.length_of_flow_description;

      try {
        if (bpf_pdr.pdi.sdf_filter.flow_desc_len >=
            sizeof(bpf_pdr.pdi.sdf_filter.flow_description)) {
          Logger::upf_app().debug(
              "SDF Filter Lengh (%d) exceeds buffer size (%d), Truncating "
              "data.",
              bpf_pdr.pdi.sdf_filter.flow_desc_len,
              sizeof(pdr->pdi.second.sdf_filter.second.flow_description));

          throw std::runtime_error("SDF filter length exceeds buffer size.");
        }

        memcpy(
            bpf_pdr.pdi.sdf_filter.flow_description,
            pdr->pdi.second.sdf_filter.second.flow_description.c_str(),
            bpf_pdr.pdi.sdf_filter.flow_desc_len);

      } catch (const std::bad_alloc& e) {
        // Handle memory allocation failure
        Logger::upf_app().error(
            "Memory allocation failed while copying SDF filter: {}", e.what());

        throw;  // Rethrow the exception
      } catch (const std::exception& e) {
        // Catch any other exception
        Logger::upf_app().error(
            "An error occurred while processing the SDF filter: {}", e.what());

        throw;  // Rethrow the exception
      } catch (...) {
        // Catch all other unspecified errors
        Logger::upf_app().error(
            "An unexpected error occurred while copying the SDF filter.");

        throw std::runtime_error(
            "Unexpected error occurred while copying SDF filter.");
      }
    }

    // QFI (3GPP TS 29.244 Section 8.2.89)
    if (pdr->pdi.second.qfi.first) {
      bpf_pdr.pdi.qfi.qfi = pdr->pdi.second.qfi.second.qfi;
    }
  }

  // if (pdr->activate_predefined_rules.first) {
  //   memcpy(
  //       &bpf_pdr.activate_predefined_rules, &pdr->activate_predefined_rules,
  //       sizeof(struct activate_predefined_rules));
  // }

  if (pdr->outer_header_removal.first) {
    memcpy(
        &bpf_pdr.outer_header_removal, &pdr->outer_header_removal,
        sizeof(struct outer_header_removal));
  }

  return bpf_pdr;
}

//------------------------------------------------------------------------------
struct pfcp_qer ConvertQer(
    std::shared_ptr<pfcp::pfcp_qer> qer) {
  struct pfcp_qer bpf_qer = {};

  if (!qer) return bpf_qer;

  // QER ID (3GPP TS 29.244 Section 8.2.11)
  bpf_qer.qer_id.qer_id = qer->qer_id.second.qer_id;

  // Gate Status (3GPP TS 29.244 Section 8.2.25)
  if (qer->gate_status.first) {
    bpf_qer.gate_status.ul_gate = qer->gate_status.second.ul_gate;
    bpf_qer.gate_status.dl_gate = qer->gate_status.second.dl_gate;
  }

  // MBR - Maximum Bitrate (3GPP TS 29.244 Section 8.2.40)
  if (qer->maximum_bitrate.first) {
    bpf_qer.maximum_bitrate.ul_mbr = qer->maximum_bitrate.second.ul_mbr;
    bpf_qer.maximum_bitrate.dl_mbr = qer->maximum_bitrate.second.dl_mbr;
  }

  // GBR - Guaranteed Bitrate (3GPP TS 29.244 Section 8.2.41)
  if (qer->guaranteed_bitrate.first) {
    bpf_qer.guaranteed_bitrate.ul_gbr = qer->guaranteed_bitrate.second.ul_gbr;
    bpf_qer.guaranteed_bitrate.dl_gbr = qer->guaranteed_bitrate.second.dl_gbr;
  }

  // QFI (3GPP TS 29.244 Section 8.2.89)
  if (qer->qos_flow_id.first) {
    bpf_qer.qos_flow_identifier.qfi = qer->qos_flow_id.second.qfi;
  }

  // if (qer->qer_correlation_id.first) {
  //   bpf_qer.qer_correlation_id.qer_correlation_id =
  //       qer->qer_correlation_id.second.qer_correlation_id;
  // }

  if (qer->reflective_qos.first) {
    bpf_qer.reflective_qos.rqi = qer->reflective_qos.second.rqi;
  }

  return bpf_qer;
}

//------------------------------------------------------------------------------
struct pfcp_urr ConvertUrr(
    std::shared_ptr<pfcp::pfcp_urr> urr) {
  struct pfcp_urr bpf_urr = {};

  if (!urr) return bpf_urr;

  bpf_urr.urr_id = urr->urr_id.second.urr_id;

  // Reporting Triggers (Section 8.2.53)
  if (urr->reporting_triggers.first) {
    bpf_urr.reporting_triggers.volth =
        urr->reporting_triggers.second.volth ? 1 : 0;
    bpf_urr.reporting_triggers.volqu =
        urr->reporting_triggers.second.volqu ? 1 : 0;
    bpf_urr.reporting_triggers.timth =
        urr->reporting_triggers.second.timth ? 1 : 0;
    bpf_urr.reporting_triggers.timqu =
        urr->reporting_triggers.second.timqu ? 1 : 0;
    bpf_urr.reporting_triggers.perio =
        urr->reporting_triggers.second.perio ? 1 : 0;
    bpf_urr.reporting_triggers.start =
        urr->reporting_triggers.second.start ? 1 : 0;
    bpf_urr.reporting_triggers.stop =
        urr->reporting_triggers.second.stop ? 1 : 0;
    bpf_urr.reporting_triggers.droth =
        urr->reporting_triggers.second.droth ? 1 : 0;
  }

  // Volume Threshold (Section 8.2.48)
  if (urr->volume_threshold.first) {
    bpf_urr.volume_threshold.total_volume =
        urr->volume_threshold.second.total_volume;
    bpf_urr.volume_threshold.uplink_volume =
        urr->volume_threshold.second.uplink_volume;
    bpf_urr.volume_threshold.downlink_volume =
        urr->volume_threshold.second.downlink_volume;
  }

  // Volume Quota (Section 8.2.46)
  if (urr->volume_quota.first) {
    bpf_urr.volume_quota.total_volume  = urr->volume_quota.second.total_volume;
    bpf_urr.volume_quota.uplink_volume = urr->volume_quota.second.uplink_volume;
    bpf_urr.volume_quota.downlink_volume =
        urr->volume_quota.second.downlink_volume;
  }

  // Measurement Period (Section 8.2.72) — convert seconds to nanoseconds
  if (urr->measurement_period.first) {
    bpf_urr.measurement_period.measurement_period =
        static_cast<uint64_t>(
            urr->measurement_period.second.measurement_period) *
        1000000000ULL;
  }

  // Time Threshold (Section 8.2.48) — convert seconds to nanoseconds
  if (urr->time_threshold.first) {
    bpf_urr.time_threshold.time_threshold =
        static_cast<uint64_t>(urr->time_threshold.second.time_threshold) *
        1000000000ULL;
  }

  // Monitoring Time (Section 8.2.67) — convert NTP epoch to nanoseconds
  if (urr->monitoring_time.first) {
    bpf_urr.monitoring_time.monitoring_time =
        static_cast<uint64_t>(urr->monitoring_time.second.monitoring_time) *
        1000000000ULL;
  }

  // Dropped DL Traffic Threshold (Section 8.2.49)
  if (urr->dropped_dl_traffic_threshold.first) {
    const auto& ddth = urr->dropped_dl_traffic_threshold.second;
    bpf_urr.dropped_dl_traffic_threshold.flags = 0;

    if (ddth.dlpa) {
      bpf_urr.dropped_dl_traffic_threshold.flags |= DDTH_FLAG_DLPA;
      bpf_urr.dropped_dl_traffic_threshold.downlink_packets =
          ddth.downlink_packets;
    }
    if (ddth.dlby) {
      bpf_urr.dropped_dl_traffic_threshold.flags |= DDTH_FLAG_DLBY;
      bpf_urr.dropped_dl_traffic_threshold.number_of_bytes_of_downlink_data =
          ddth.number_of_bytes_of_downlink_data;
    }
  }

  return bpf_urr;
}

//------------------------------------------------------------------------------
struct pfcp_bar ConvertBar(
    std::shared_ptr<pfcp::pfcp_bar> bar) {
  struct pfcp_bar bpf_bar = {};

  if (!bar) return bpf_bar;

  bpf_bar.bar_id = bar->bar_id.second.bar_id;

  // Suggested Buffering Packets Count (Section 8.2.50)
  if (bar->suggested_buffering_packets_count.first) {
    bpf_bar.suggested_buffering_packets_count.packet_count =
        bar->suggested_buffering_packets_count.second.packet_count;
  }

  // DL Data Notification Delay (Section 8.2.28) — in seconds
  if (bar->downlink_data_notification_delay.first) {
    bpf_bar.dl_data_notification_delay.delay_value =
        bar->downlink_data_notification_delay.second.delay_value;
  }

  return bpf_bar;
}

//------------------------------------------------------------------------------
struct pfcp_mar ConvertMar(
    std::shared_ptr<pfcp::pfcp_mar> mar) {
  struct pfcp_mar bpf_mar = {};

  if (!mar) return bpf_mar;

  bpf_mar.mar_id = mar->mar_id.second.mar_id;

  // Steering Mode (Section 8.2.124)
  if (mar->steering_mode.first) {
    bpf_mar.steering_mode.steer_mode_value =
        mar->steering_mode.second.steering_mode_value;
  }

  // Access Forwarding Action Information - 3GPP (Section 8.2.75)
  if (mar->access_forwarding_action_info_1.first) {
    bpf_mar.access_forwarding_action_info_1.far_id.far_id =
        mar->access_forwarding_action_info_1.second.far_id.far_id;
  }

  // Access Forwarding Action Information - Non-3GPP (Section 8.2.76)
  if (mar->access_forwarding_action_info_2.first) {
    bpf_mar.access_forwarding_action_info_2.far_id.far_id =
        mar->access_forwarding_action_info_2.second.far_id.far_id;
  }

  return bpf_mar;
}

}  // namespace rules
