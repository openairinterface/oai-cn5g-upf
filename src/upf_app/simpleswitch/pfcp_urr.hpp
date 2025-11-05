/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file pfcp_urr.hpp
   \author  Your Name
   \date 2024
   \email: your.email@example.com
*/

#ifndef FILE_PFCP_URR_HPP_SEEN
#define FILE_PFCP_URR_HPP_SEEN

#include <linux/ip.h>
#include <linux/ipv6.h>
#include "msg_pfcp.hpp"
#include <chrono>
#include <mutex>

namespace pfcp {

class pfcp_urr {
 public:
  mutable std::mutex lock;

  pfcp::urr_id_t urr_id;
  std::pair<bool, pfcp::measurement_method_t> measurement_method;
  std::pair<bool, pfcp::reporting_triggers_t> reporting_triggers;
  std::pair<bool, pfcp::measurement_period_t> measurement_period;
  std::pair<bool, pfcp::volume_threshold_t> volume_threshold;
  std::pair<bool, pfcp::volume_quota_t> volume_quota;
  std::pair<bool, pfcp::time_threshold_t> time_threshold;
  std::pair<bool, pfcp::time_quota_t> time_quota;
  std::pair<bool, pfcp::monitoring_time_t> monitoring_time;
  std::pair<bool, pfcp::subsequent_volume_threshold_t>
      subsequent_volume_threshold;
  std::pair<bool, pfcp::subsequent_time_threshold_t> subsequent_time_threshold;
  std::pair<bool, pfcp::subsequent_volume_quota_t> subsequent_volume_quota;
  std::pair<bool, pfcp::subsequent_time_quota_t> subsequent_time_quota;
  std::pair<bool, pfcp::inactivity_detection_time_t> inactivity_detection_time;
  std::pair<bool, pfcp::linked_urr_id_t> linked_urr_id;
  std::pair<bool, pfcp::measurement_information_t> measurement_information;
  std::pair<bool, pfcp::time_quota_mechanism_t> time_quota_mechanism;
  std::pair<bool, pfcp::aggregated_urrs> aggregated_urrs;
  std::pair<bool, pfcp::far_id_t> far_id_for_quota_action;
  std::pair<bool, pfcp::ethernet_inactivity_timer_t> ethernet_inactivity_timer;
  std::pair<bool, pfcp::additional_monitoring_time> additional_monitoring_time;

  // Runtime measurement data
  struct measurement_data_t {
    uint64_t total_volume;
    uint64_t uplink_volume;
    uint64_t downlink_volume;
    uint64_t total_packets;
    uint64_t uplink_packets;
    uint64_t downlink_packets;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    std::chrono::steady_clock::time_point last_packet_time;
    uint32_t duration_seconds;

    measurement_data_t()
        : total_volume(0),
          uplink_volume(0),
          downlink_volume(0),
          total_packets(0),
          uplink_packets(0),
          downlink_packets(0),
          duration_seconds(0) {}
  } measurement_data;

  //------------------------------------------------------------------------------
  pfcp_urr()
      : lock(),
        urr_id(),
        measurement_method(),
        reporting_triggers(),
        measurement_period(),
        volume_threshold(),
        volume_quota(),
        time_threshold(),
        time_quota(),
        monitoring_time(),
        subsequent_volume_threshold(),
        subsequent_time_threshold(),
        subsequent_volume_quota(),
        subsequent_time_quota(),
        inactivity_detection_time(),
        linked_urr_id(),
        measurement_information(),
        time_quota_mechanism(),
        aggregated_urrs(),
        far_id_for_quota_action(),
        ethernet_inactivity_timer(),
        additional_monitoring_time(),
        measurement_data() {}

  //------------------------------------------------------------------------------
  explicit pfcp_urr(const pfcp::create_urr& c)
      : lock(),
        urr_id(c.urr_id.second),
        measurement_method(c.measurement_method),
        reporting_triggers(c.reporting_triggers),
        measurement_period(c.measurement_period),
        volume_threshold(c.volume_threshold),
        volume_quota(c.volume_quota),
        time_threshold(c.time_threshold),
        time_quota(c.time_quota),
        monitoring_time(c.monitoring_time),
        subsequent_volume_threshold(c.subsequent_volume_threshold),
        subsequent_time_threshold(c.subsequent_time_threshold),
        subsequent_volume_quota(c.subsequent_volume_quota),
        subsequent_time_quota(c.subsequent_time_quota),
        inactivity_detection_time(c.inactivity_detection_time),
        linked_urr_id(c.linked_urr_id),
        measurement_information(c.measurement_information),
        time_quota_mechanism(c.time_quota_mechanism),
        aggregated_urrs(c.aggregated_urrs),
        far_id_for_quota_action(c.far_id_for_quota_action),
        ethernet_inactivity_timer(c.ethernet_inactivity_timer),
        additional_monitoring_time(c.additional_monitoring_time),
        measurement_data() {
    // Initialize measurement start time if measurement is active
    if (measurement_method.first) {
      measurement_data.start_time = std::chrono::steady_clock::now();
    }
  }

  //------------------------------------------------------------------------------
  pfcp_urr(const pfcp_urr& c)
      : lock(),
        urr_id(c.urr_id),
        measurement_method(c.measurement_method),
        reporting_triggers(c.reporting_triggers),
        measurement_period(c.measurement_period),
        volume_threshold(c.volume_threshold),
        volume_quota(c.volume_quota),
        time_threshold(c.time_threshold),
        time_quota(c.time_quota),
        monitoring_time(c.monitoring_time),
        subsequent_volume_threshold(c.subsequent_volume_threshold),
        subsequent_time_threshold(c.subsequent_time_threshold),
        subsequent_volume_quota(c.subsequent_volume_quota),
        subsequent_time_quota(c.subsequent_time_quota),
        inactivity_detection_time(c.inactivity_detection_time),
        linked_urr_id(c.linked_urr_id),
        measurement_information(c.measurement_information),
        time_quota_mechanism(c.time_quota_mechanism),
        aggregated_urrs(c.aggregated_urrs),
        far_id_for_quota_action(c.far_id_for_quota_action),
        ethernet_inactivity_timer(c.ethernet_inactivity_timer),
        additional_monitoring_time(c.additional_monitoring_time),
        measurement_data(c.measurement_data) {}

  //------------------------------------------------------------------------------
  void set(const pfcp::urr_id_t& v) { urr_id = v; }

  void set(const pfcp::measurement_method_t& v) {
    measurement_method.first  = true;
    measurement_method.second = v;
  }

  void set(const pfcp::reporting_triggers_t& v) {
    reporting_triggers.first  = true;
    reporting_triggers.second = v;
  }

  void set(const pfcp::measurement_period_t& v) {
    measurement_period.first  = true;
    measurement_period.second = v;
  }

  void set(const pfcp::volume_threshold_t& v) {
    volume_threshold.first  = true;
    volume_threshold.second = v;
  }

  void set(const pfcp::volume_quota_t& v) {
    volume_quota.first  = true;
    volume_quota.second = v;
  }

  void set(const pfcp::time_threshold_t& v) {
    time_threshold.first  = true;
    time_threshold.second = v;
  }

  void set(const pfcp::time_quota_t& v) {
    time_quota.first  = true;
    time_quota.second = v;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::urr_id_t& v) const {
    v = urr_id;
    return true;
  }

  bool get(pfcp::measurement_method_t& v) const {
    if (measurement_method.first) {
      v = measurement_method.second;
      return true;
    }
    return false;
  }

  bool get(pfcp::reporting_triggers_t& v) const {
    if (reporting_triggers.first) {
      v = reporting_triggers.second;
      return true;
    }
    return false;
  }

  bool get(pfcp::volume_threshold_t& v) const {
    if (volume_threshold.first) {
      v = volume_threshold.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool update(const pfcp::update_urr& update, uint8_t& cause_value);

  // Measurement operations
  void start_measurement();
  void stop_measurement();
  void update_measurement(uint64_t bytes, bool is_uplink, bool is_downlink);
  bool check_thresholds_exceeded();
  bool check_quotas_exceeded();
  void generate_usage_report(
      pfcp::usage_report_within_pfcp_session_report_request& report);
  void reset_measurement();
};

}  // namespace pfcp

#endif