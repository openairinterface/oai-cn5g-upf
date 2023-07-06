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

#pragma once

#include "config.hpp"
#include "upf_config.hpp"

constexpr auto UPF_CONFIG_INSTANCE_ID            = "instance_id";
constexpr auto UPF_CONFIG_INSTANCE_ID_LABEL      = "Instance ID";
constexpr auto UPF_CONFIG_PID_DIRECTORY          = "pid_directory";
constexpr auto UPF_CONFIG_PID_DIRECTORY_LABEL    = "PID Directory";
constexpr auto UPF_CONFIG_UPF_NAME               = "upf_name";
constexpr auto UPF_CONFIG_UPF_NAME_LABEL         = "UPF Name";
constexpr auto UPF_CONFIG_SUPPORT_FEATURES       = "support_features";
constexpr auto UPF_CONFIG_SUPPORT_FEATURES_LABEL = "Support Features";
constexpr auto UPF_CONFIG_UPF_INFO_LABEL         = "UPF INFO";
constexpr auto UPF_CONFIG_UPF_INFO               = "upf_info";

constexpr auto UPF_CONFIG_SUPPORT_FEATURES_ENABLE_BPF = "enable_bpf_datapath";
constexpr auto UPF_CONFIG_SUPPORT_FEATURES_ENABLE_BPF_LABEL =
    "Enable BPF Datapath";
constexpr auto UPF_CONFIG_SUPPORT_FEATURES_ENABLE_SNAT       = "enable_snat";
constexpr auto UPF_CONFIG_SUPPORT_FEATURES_ENABLE_SNAT_LABEL = "Enable SNAT";

constexpr auto UPF_CONFIG_N3_LABEL = "n3";
constexpr auto UPF_CONFIG_N6_LABEL = "n6";
constexpr auto UPF_CONFIG_N4_LABEL = "n4";

namespace oai::config {
class upf_support_features : public config_type {
 private:
  option_config_value m_enable_bpf_datapath{};
  option_config_value m_enable_snat{};

 public:
  explicit upf_support_features(bool enable_bpf_datapath, bool enable_snat);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] bool get_option_enable_bpf_datapath() const;
  [[nodiscard]] bool get_option_enable_snat() const;
};

class upf_info_config : public config_type {
 private:
  int_config_value m_sd;
  int_config_value m_sst;
  snssai_t m_snssai;
  string_config_value m_dnn;
  std::vector<interface_upf_info_item_t> m_interface_item_list;
  std::vector<snssai_upf_info_item_t> m_snssai_item_list;

 public:
  explicit upf_info_config(
      const snssai_t& snssai, const std::vector<std::string>& dnn);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  void validate() override;

  [[nodiscard]] const snssai_t& get_snssai() const;

  [[nodiscard]] const std::vector<snssai_upf_info_item_t>&
  get_snssai_upf_info_item() const;
};

class upf_interface_config : public local_interface {
 private:
  string_config_value m_nwi;
  string_config_value m_interface_type;

 public:
  explicit upf_interface_config(
      const std::string& name, const std::string& host, uint16_t port,
      const std::string& if_name, const std::string& if_type);

  explicit upf_interface_config(
      const std::string& name, const std::string& host, uint16_t port,
      const std::string& if_name, const std::string& if_type,
      const std::string& nwi);

  void from_yaml(const YAML::Node& node) override;

  void set_if_type(const std::string& if_type);

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  [[nodiscard]] interface_upf_info_item_t to_upf_info_item() const;

  [[nodiscard]] interface_cfg_t to_interface_config() const;
};

class upf_config_yaml : public config {
 public:
  explicit upf_config_yaml(
      const std::string& config_path, bool log_stdout, bool log_rot_file);
  virtual ~upf_config_yaml();

  void to_upf_config(oai::config::upf_config& cfg);
  void pre_process();

  static upf_interface_config get_default_n3_interface();

  static upf_interface_config get_default_n4_interface();

  static upf_interface_config get_default_n6_interface();
};

class upf : public nf {
 private:
  int_config_value m_instance_id;
  string_config_value m_pid_directory;
  string_config_value m_upf_name;
  upf_support_features m_upf_support_features;
  upf_info_config m_upf_info_config;
  // the reason to use a map is to have support for different interfaces in the
  // future now we use N3, N6 or N4 as key, but then we can have N3_NWI to
  // support multiple use cases or several N6/N9 (e.g. for UL CL)
  std::map<std::string, upf_interface_config> m_interfaces;

  void create_or_update_interface(
      const std::string& iface_type, const YAML::Node& node,
      const upf_interface_config& default_config);

 public:
  explicit upf(
      const std::string& name, const std::string& host,
      const sbi_interface& sbi,
      const std::map<std::string, upf_interface_config>& interfaces);

  void from_yaml(const YAML::Node& node) override;

  void validate() override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] const uint32_t get_instance_id() const;
  [[nodiscard]] const std::string get_pid_directory() const;
  [[nodiscard]] const std::string get_upf_name() const;
  [[nodiscard]] const upf_support_features& get_support_features() const;
  [[nodiscard]] const upf_info_config& get_upf_info() const;
  [[nodiscard]] const std::map<std::string, upf_interface_config>&
  get_interfaces() const;
};

}  // namespace oai::config
