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

/*! \file pfcp_urr.cpp
   \author  Your Name
   \date 2024
   \email: your.email@example.com
*/

#include "pfcp_urr.hpp"
#include "logger.hpp"
#include <ctime>

using namespace pfcp;

//------------------------------------------------------------------------------
bool pfcp_urr::update(const pfcp::update_urr& update, uint8_t& cause_value) {
  std::lock_guard<std::mutex> lock_guard(lock);

  if (update.get(measurement_method.second)) measurement_method.first = true;

  if (update.get(reporting_triggers.second)) reporting_triggers.first = true;

  if (update.get(measurement_period.second)) measurement_period.first = true;

  if (update.get(volume_threshold.second)) volume_threshold.first = true;

  if (update.get(volume_quota.second)) volume_quota.first = true;

  if (update.get(time_threshold.second)) time_threshold.first = true;

  if (update.get(time_quota.second)) time_quota.first = true;

  if (update.get(monitoring_time.second)) monitoring_time.first = true;

  if (update.get(subsequent_volume_threshold.second))
    subsequent_volume_threshold.first = true;

  if (update.get(subsequent_time_threshold.second))
    subsequent_time_threshold.first = true;

  if (update.get(inactivity_detection_time.second))
    inactivity_detection_time.first = true;

  // Reset measurement if triggers changed
  if (update.reporting_triggers.first) {
    reset_measurement();
  }

  cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}

//------------------------------------------------------------------------------
void pfcp_urr::start_measurement() {
  std::lock_guard<std::mutex> lock_guard(lock);

  measurement_data.start_time       = std::chrono::steady_clock::now();
  measurement_data.last_packet_time = measurement_data.start_time;

  Logger::upf_n4().debug("URR ID %d: Starting measurement", urr_id.urr_id);
}

//------------------------------------------------------------------------------
void pfcp_urr::stop_measurement() {
  std::lock_guard<std::mutex> lock_guard(lock);

  measurement_data.end_time = std::chrono::steady_clock::now();

  auto duration = std::chrono::duration_cast<std::chrono::seconds>(
      measurement_data.end_time - measurement_data.start_time);
  measurement_data.duration_seconds = duration.count();

  Logger::upf_n4().debug(
      "URR ID %d: Stopping measurement - Duration: %d seconds, "
      "Total Volume: %lu bytes, UL: %lu, DL: %lu",
      urr_id.urr_id, measurement_data.duration_seconds,
      measurement_data.total_volume, measurement_data.uplink_volume,
      measurement_data.downlink_volume);
}

//------------------------------------------------------------------------------
void pfcp_urr::update_measurement(
    uint64_t bytes, bool is_uplink, bool is_downlink) {
  std::lock_guard<std::mutex> lock_guard(lock);

  if (!measurement_method.first) {
    return;
  }

  // Update volume measurements
  if (measurement_method.second.volum) {
    measurement_data.total_volume += bytes;

    if (is_uplink) {
      measurement_data.uplink_volume += bytes;
      measurement_data.uplink_packets++;
    }

    if (is_downlink) {
      measurement_data.downlink_volume += bytes;
      measurement_data.downlink_packets++;
    }

    measurement_data.total_packets++;
  }

  // Update last packet time for inactivity detection
  measurement_data.last_packet_time = std::chrono::steady_clock::now();

  // Update duration if measuring time
  if (measurement_method.second.durat) {
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        measurement_data.last_packet_time - measurement_data.start_time);
    measurement_data.duration_seconds = duration.count();
  }
}

//------------------------------------------------------------------------------
bool pfcp_urr::check_thresholds_exceeded() {
  std::lock_guard<std::mutex> lock_guard(lock);

  // Check volume threshold
  if (volume_threshold.first) {
    if (volume_threshold.second.tovol &&
        measurement_data.total_volume >= volume_threshold.second.total_volume) {
      Logger::upf_n4().info(
          "URR ID %d: Total volume threshold exceeded (%lu >= %lu)",
          urr_id.urr_id, measurement_data.total_volume,
          volume_threshold.second.total_volume);
      return true;
    }

    if (volume_threshold.second.ulvol &&
        measurement_data.uplink_volume >=
            volume_threshold.second.uplink_volume) {
      Logger::upf_n4().info(
          "URR ID %d: Uplink volume threshold exceeded (%lu >= %lu)",
          urr_id.urr_id, measurement_data.uplink_volume,
          volume_threshold.second.uplink_volume);
      return true;
    }

    if (volume_threshold.second.dlvol &&
        measurement_data.downlink_volume >=
            volume_threshold.second.downlink_volume) {
      Logger::upf_n4().info(
          "URR ID %d: Downlink volume threshold exceeded (%lu >= %lu)",
          urr_id.urr_id, measurement_data.downlink_volume,
          volume_threshold.second.downlink_volume);
      return true;
    }
  }

  // Check time threshold
  if (time_threshold.first) {
    if (measurement_data.duration_seconds >=
        time_threshold.second.time_threshold) {
      Logger::upf_n4().info(
          "URR ID %d: Time threshold exceeded (%d >= %d)", urr_id.urr_id,
          measurement_data.duration_seconds,
          time_threshold.second.time_threshold);
      return true;
    }
  }

  return false;
}

//------------------------------------------------------------------------------
bool pfcp_urr::check_quotas_exceeded() {
  std::lock_guard<std::mutex> lock_guard(lock);

  // Check volume quota
  if (volume_quota.first) {
    if (volume_quota.second.tovol &&
        measurement_data.total_volume >= volume_quota.second.total_volume) {
      Logger::upf_n4().warn(
          "URR ID %d: Total volume quota exceeded (%lu >= %lu)", urr_id.urr_id,
          measurement_data.total_volume, volume_quota.second.total_volume);
      return true;
    }

    if (volume_quota.second.ulvol &&
        measurement_data.uplink_volume >= volume_quota.second.uplink_volume) {
      Logger::upf_n4().warn(
          "URR ID %d: Uplink volume quota exceeded (%lu >= %lu)", urr_id.urr_id,
          measurement_data.uplink_volume, volume_quota.second.uplink_volume);
      return true;
    }

    if (volume_quota.second.dlvol && measurement_data.downlink_volume >=
                                         volume_quota.second.downlink_volume) {
      Logger::upf_n4().warn(
          "URR ID %d: Downlink volume quota exceeded (%lu >= %lu)",
          urr_id.urr_id, measurement_data.downlink_volume,
          volume_quota.second.downlink_volume);
      return true;
    }
  }

  // Check time quota
  if (time_quota.first) {
    if (measurement_data.duration_seconds >= time_quota.second.time_quota) {
      Logger::upf_n4().warn(
          "URR ID %d: Time quota exceeded (%d >= %d)", urr_id.urr_id,
          measurement_data.duration_seconds, time_quota.second.time_quota);
      return true;
    }
  }

  return false;
}

//------------------------------------------------------------------------------
void pfcp_urr::generate_usage_report(
    pfcp::usage_report_within_pfcp_session_report_request& report) {
  std::lock_guard<std::mutex> lock_guard(lock);

  // Set URR ID
  report.urr_id.first  = true;
  report.urr_id.second = urr_id;

  // Set usage report trigger
  if (reporting_triggers.first) {
    report.usage_report_trigger.first  = true;
    report.usage_report_trigger.second = reporting_triggers.second;
  }

  // Set start time (convert to NTP timestamp)
  report.start_time.first = true;
  auto start_time_t       = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now() -
      (std::chrono::steady_clock::now() - measurement_data.start_time));
  report.start_time.second.start_time = static_cast<uint32_t>(start_time_t);

  // Set end time
  report.end_time.first = true;
  auto end_time_t       = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now() -
      (std::chrono::steady_clock::now() - measurement_data.end_time));
  report.end_time.second.end_time = static_cast<uint32_t>(end_time_t);

  // Set volume measurement
  if (measurement_method.first && measurement_method.second.volum) {
    report.volume_measurement.first        = true;
    report.volume_measurement.second.tovol = 1;
    report.volume_measurement.second.ulvol = 1;
    report.volume_measurement.second.dlvol = 1;
    report.volume_measurement.second.total_volume =
        measurement_data.total_volume;
    report.volume_measurement.second.uplink_volume =
        measurement_data.uplink_volume;
    report.volume_measurement.second.downlink_volume =
        measurement_data.downlink_volume;
  }

  // Set duration measurement
  if (measurement_method.first && measurement_method.second.durat) {
    report.duration_measurement.first = true;
    report.duration_measurement.second.duration =
        measurement_data.duration_seconds;
  }

  Logger::upf_n4().info(
      "URR ID %d: Generated usage report - Volume: %lu bytes, Duration: %d "
      "seconds",
      urr_id.urr_id, measurement_data.total_volume,
      measurement_data.duration_seconds);
}

//------------------------------------------------------------------------------
void pfcp_urr::reset_measurement() {
  std::lock_guard<std::mutex> lock_guard(lock);

  Logger::upf_n4().debug("URR ID %d: Resetting measurement", urr_id.urr_id);

  measurement_data                  = measurement_data_t();
  measurement_data.start_time       = std::chrono::steady_clock::now();
  measurement_data.last_packet_time = measurement_data.start_time;
}