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

#include "upf_config_yaml.hpp"

#include <boost/algorithm/string.hpp>
#include <regex>

#include "conversions.hpp"
#include "fqdn.hpp"
#include "logger.hpp"

namespace oai::config {

//------------------------------------------------------------------------------
//          * Support Features *
//------------------------------------------------------------------------------

upf_support_features::upf_support_features(
    bool enable_bpf_datapath, bool enable_qos, bool enable_urr, bool enable_bar,
    bool enable_mar, bool enable_snat, bool enable_fr, bool enable_eth_pdu) {
  m_config_name = "Supported Features";

  // Performance
  m_enable_bpf_datapath =
      option_config_value(UPF_ENABLE_BPF_LABEL, enable_bpf_datapath);
  m_enable_eth_pdu =
      option_config_value(UPF_ENABLE_ETH_PDU_LABEL, enable_eth_pdu);
  m_enable_fr   = option_config_value(UPF_ENABLE_FR_LABEL, enable_fr);
  m_enable_qos  = option_config_value(UPF_ENABLE_QOS_LABEL, enable_qos);
  m_enable_urr  = option_config_value(UPF_ENABLE_URR_LABEL, enable_urr);
  m_enable_bar  = option_config_value(UPF_ENABLE_BAR_LABEL, enable_bar);
  m_enable_mar  = option_config_value(UPF_ENABLE_MAR_LABEL, enable_mar);
  m_enable_snat = option_config_value(UPF_ENABLE_SNAT_LABEL, false);
}

//------------------------------------------------------------------------------
void upf_support_features::from_yaml(const YAML::Node& node) {
  // Performance
  if (node[UPF_ENABLE_BPF]) {
    m_enable_bpf_datapath.from_yaml(node[UPF_ENABLE_BPF]);
  }

  // Ethernet PDU Sessions
  if (node[UPF_ENABLE_ETH_PDU]) {
    m_enable_eth_pdu.from_yaml(node[UPF_ENABLE_ETH_PDU]);
  }

  // PFCP Rules - Framed Routing (FR)
  if (node[UPF_ENABLE_FR]) {
    m_enable_fr.from_yaml(node[UPF_ENABLE_FR]);
  }

  // PFCP Rules - QoS (QER)
  if (node[UPF_ENABLE_QOS]) {
    m_enable_qos.from_yaml(node[UPF_ENABLE_QOS]);
  }

  // PFCP Rules - Usage Reporting (URR)
  if (node[UPF_ENABLE_URR]) {
    m_enable_urr.from_yaml(node[UPF_ENABLE_URR]);
  }

  // PFCP Rules - Packet Buffering (BAR)
  if (node[UPF_ENABLE_BAR]) {
    m_enable_bar.from_yaml(node[UPF_ENABLE_BAR]);
  }

  // PFCP Rules - Multi-Steering (MAR)
  if (node[UPF_ENABLE_MAR]) {
    m_enable_mar.from_yaml(node[UPF_ENABLE_MAR]);
  }

  // Network Features Source Nat (SNAT)
  if (node[UPF_ENABLE_SNAT]) {
    m_enable_snat.from_yaml(node[UPF_ENABLE_SNAT]);
    // Force to false - no implementation yet
    if (m_enable_snat.get_value()) {
      logger::logger_registry::get_logger(LOGGER_NAME)
          .warn(
              "SNAT (Source Network Address Translation) requested but not "
              "implemented within UPF - "
              "forcing to disabled. Check the Ext-DN for SNAT configuration");
      m_enable_mar = option_config_value(UPF_ENABLE_MAR_LABEL, false);
    }
  }
}

//------------------------------------------------------------------------------
std::string upf_support_features::to_string(const std::string& indent) const {
  std::string out;
  unsigned int inner_width = get_inner_width(indent.length());

  // Performance
  std::string enable_bpf_datapath = m_enable_bpf_datapath.get_value() ?
                                        UPF_CONFIG_OPTION_YES_STR :
                                        UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, UPF_ENABLE_BPF_LABEL, inner_width,
      enable_bpf_datapath));

  // PFCP Rules - QoS (QER)
  std::string enable_qos = m_enable_qos.get_value() ?
                               UPF_CONFIG_OPTION_YES_STR :
                               UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, UPF_ENABLE_QOS_LABEL, inner_width,
      enable_qos));

  // PFCP Rules - URR (Usage Reporting Rule)
  std::string enable_urr = m_enable_urr.get_value() ?
                               UPF_CONFIG_OPTION_YES_STR :
                               UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, UPF_ENABLE_URR_LABEL, inner_width,
      enable_urr));

  // PFCP Rules - BAR (Buffering Action Rule)
  std::string enable_bar = m_enable_bar.get_value() ?
                               UPF_CONFIG_OPTION_YES_STR :
                               UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, UPF_ENABLE_BAR_LABEL, inner_width,
      enable_bar));

  // PFCP Rules - MAR (Modify Access Rule)
  std::string enable_mar = m_enable_mar.get_value() ?
                               UPF_CONFIG_OPTION_YES_STR :
                               UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, UPF_ENABLE_MAR_LABEL, inner_width,
      enable_mar));

  // Network Features - SNAT
  std::string enable_snat = m_enable_snat.get_value() ?
                                UPF_CONFIG_OPTION_YES_STR :
                                UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, UPF_ENABLE_SNAT_LABEL, inner_width,
      enable_snat));

  // Network Features - Framed Routing
  std::string enable_fr = m_enable_fr.get_value() ? UPF_CONFIG_OPTION_YES_STR :
                                                    UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, UPF_ENABLE_FR_LABEL, inner_width,
      enable_fr));

  // Network Features - Ethernet PDU Sessions
  std::string enable_eth_pdu = m_enable_eth_pdu.get_value() ?
                                   UPF_CONFIG_OPTION_YES_STR :
                                   UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, UPF_ENABLE_ETH_PDU_LABEL, inner_width,
      enable_eth_pdu));

  return out;
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_bpf_datapath() const {
  return m_enable_bpf_datapath.get_value();
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_qos() const {
  return m_enable_qos.get_value();
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_urr() const {
  return m_enable_urr.get_value();
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_bar() const {
  return m_enable_bar.get_value();
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_mar() const {
  return m_enable_mar.get_value();
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_snat() const {
  return m_enable_snat.get_value();  // Always returns false for now
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_fr() const {
  return m_enable_fr.get_value();
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_eth_pdu() const {
  return m_enable_eth_pdu.get_value();
}

//------------------------------------------------------------------------------
const upf_support_features& upf::get_support_features() const {
  return m_upf_support_features;
}

//------------------------------------------------------------------------------
//          * UPF *
//------------------------------------------------------------------------------
upf::upf(
    const std::string& name, const std::string& host, const sbi_interface& sbi,
    const std::map<std::string, upf_interface_config>& interfaces)
    : nf(name, host, sbi),
      m_upf_support_features(
          false, false, false, false, false, false, false, false),
      m_upf_datapath_configuration(),
      m_interfaces(interfaces) {
  model::nrf::SnssaiUpfInfoItem item;
  item.setSNssai(DEFAULT_SNSSAI);
  item.setDnnUpfInfoList(DEFAULT_DNN_LIST);
  m_upf_info.setSNssaiUpfInfoList(
      std::vector<oai::model::nrf::SnssaiUpfInfoItem>{item});
}

//------------------------------------------------------------------------------
void upf::from_yaml(const YAML::Node& node) {
  nf::from_yaml(node);
  create_or_update_interface(
      UPF_CONFIG_N3_LABEL, node, upf_config_yaml::get_default_n3_interface());
  create_or_update_interface(
      UPF_CONFIG_N4_LABEL, node, upf_config_yaml::get_default_n4_interface());
  create_or_update_interface(
      UPF_CONFIG_N6_LABEL, node, upf_config_yaml::get_default_n6_interface());

  // Load UPF specified parameter
  for (const auto& elem : node) {
    auto key = elem.first.as<std::string>();

    if (key == UPF_CONFIG_INSTANCE_ID) {
      m_instance_id.from_yaml(elem.second);
    }

    if (key == UPF_CONFIG_SUPPORT_FEATURES) {
      m_upf_support_features.from_yaml(elem.second);
    }

    if (key == UPF_CONFIG_DATAPATH_CONFIGURATION) {
      m_upf_datapath_configuration.from_yaml(elem.second);
    }

    if (key == UPF_CONFIG_REMOTE_N6_GW) {
      m_remote_n6.from_yaml(elem.second);
    }

    if (key == UPF_CONFIG_SMF_LIST) {
      for (const auto& yaml_sub : node[UPF_CONFIG_SMF_LIST]) {
        string_config_value m_smf;
        if (yaml_sub["host"]) {
          m_smf.from_yaml(yaml_sub["host"]);
          m_smf_list.push_back(m_smf);
        }
      }
    }

    if (key == UPF_CONFIG_UPF_INFO) {
      nlohmann::json j =
          oai::utils::conv::yaml_to_json(node[UPF_CONFIG_UPF_INFO], false);
      nlohmann::from_json(j, m_upf_info);
    }
  }
}

//------------------------------------------------------------------------------
std::string upf::to_string(const std::string& indent) const {
  std::string out          = nf::to_string("");
  unsigned int inner_width = get_inner_width(indent.length());
  std::string inner_indent = add_indent(indent);

  for (const auto& iface : m_interfaces) {
    out.append(indent).append(fmt::format(
        "{} {}:\n", OUTER_LIST_ELEM, iface.second.get_config_name()));
    out.append(iface.second.to_string(inner_indent));
  }

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, OUTER_LIST_ELEM, UPF_CONFIG_INSTANCE_ID_LABEL,
      inner_width, m_instance_id.get_value()));

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, OUTER_LIST_ELEM, UPF_CONFIG_REMOTE_N6_GW_LABEL,
      inner_width, m_remote_n6.get_value()));

  out.append(indent).append(fmt::format(
      "{} {}:\n", OUTER_LIST_ELEM, UPF_CONFIG_SUPPORT_FEATURES_LABEL));
  out.append(m_upf_support_features.to_string(inner_indent));

  out.append(m_upf_info.to_string(1));

  return out;
}

//------------------------------------------------------------------------------
const uint32_t upf::get_instance_id() const {
  return m_instance_id.get_value();
}

//------------------------------------------------------------------------------
const std::string upf::get_remote_n6() const {
  return m_remote_n6.get_value();
}

//------------------------------------------------------------------------------
const std::vector<string_config_value> upf::get_smf_list() const {
  return m_smf_list;
}

//------------------------------------------------------------------------------
const oai::model::nrf::UpfInfo& upf::get_upf_info() const {
  return m_upf_info;
}
const std::map<std::string, upf_interface_config>& upf::get_interfaces() const {
  return m_interfaces;
}

void upf::create_or_update_interface(
    const std::string& iface_type, const YAML::Node& node,
    const upf_interface_config& default_config) {
  if (node[iface_type]) {
    auto n3 = m_interfaces.find(iface_type);
    if (n3 == m_interfaces.end()) {
      // we use the default values as template, YAML only overwrites these
      upf_interface_config new_cfg = default_config;
      new_cfg.from_yaml(node[iface_type]);
      m_interfaces.insert(std::make_pair(iface_type, new_cfg));
    } else {
      n3->second.from_yaml(node[iface_type]);
    }
  }
}

void upf::validate() {
  nf::validate();
  m_upf_support_features.validate();
  for (auto& iface : m_interfaces) {
    iface.second.validate();
  }
  m_upf_info.validate();
  m_upf_datapath_configuration.validate();
}

//------------------------------------------------------------------------------
upf_config_yaml::upf_config_yaml(
    const std::string& config_path, bool log_stdout, bool log_rot_file)
    : oai::config::config(
          config_path, oai::config::UPF_CONFIG_NAME, log_stdout, log_rot_file) {
  m_used_sbi_values = {
      oai::config::UPF_CONFIG_NAME, oai::config::SMF_CONFIG_NAME,
      oai::config::NRF_CONFIG_NAME};
  m_used_config_values = {
      oai::config::LOG_LEVEL_CONFIG_NAME, oai::config::REGISTER_NF_CONFIG_NAME,
      oai::config::NF_CONFIG_HTTP_NAME,   oai::config::NF_LIST_CONFIG_NAME,
      oai::config::UPF_CONFIG_NAME,       oai::config::DNNS_CONFIG_NAME};

  m_nf_name = UPF_CONFIG_NAME;

  // TODO with NF_Type and switch
  // TODO: Still we need to add default NFs even we don't use this in all_in_one
  // use case
  std::map<std::string, upf_interface_config> ifaces;
  ifaces.insert(
      std::make_pair(UPF_CONFIG_N3_LABEL, get_default_n3_interface()));
  ifaces.insert(
      std::make_pair(UPF_CONFIG_N4_LABEL, get_default_n4_interface()));
  ifaces.insert(
      std::make_pair(UPF_CONFIG_N6_LABEL, get_default_n6_interface()));

  auto m_upf = std::make_shared<upf>(
      "UPF Configuration", "oai-upf",
      sbi_interface("SBI", "oai-upf", 80, "v1", "eth0"), ifaces);
  add_nf(oai::config::UPF_CONFIG_NAME, m_upf);

  auto m_smf = std::make_shared<nf>(
      "SMF", "oai-smf", sbi_interface("SBI", "oai-smf", 80, "v1", "eth0"));
  add_nf(oai::config::SMF_CONFIG_NAME, m_smf);

  auto m_nrf = std::make_shared<nf>(
      "NRF", "oai-nrf", sbi_interface("SBI", "oai-nrf", 80, "v1", "eth0"));
  add_nf(oai::config::NRF_CONFIG_NAME, m_nrf);

  // DNN default values
  dnn_config dnn("default", "IPV4", "12.1.1.0/24", "");
  m_dnns.push_back(dnn);

  update_used_nfs();
}

//------------------------------------------------------------------------------
upf_config_yaml::~upf_config_yaml() {}

void upf_config_yaml::pre_process() {
  // Process configuration information to display only the appropriate
  // information
  // TODO
  std::shared_ptr<upf> upf_local = std::static_pointer_cast<upf>(get_local());
  std::shared_ptr<nf> smf        = get_nf(SMF_CONFIG_NAME);
  smf->set_config();
  std::shared_ptr<nf> nrf = get_nf(NRF_CONFIG_NAME);
  nrf->set_config();
}

//------------------------------------------------------------------------------
in_addr upf_config_yaml::resolve_nf(const std::string& host) {
  // we remove use_fqdn_dns towards the user, if it is an IPv4 we don't resolve
  std::regex re(IPV4_ADDRESS_VALIDATOR_REGEX);
  if (!std::regex_match(host, re)) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .info("Configured host %s is an FQDN. Resolve on NF startup", host);
    std::string ip_address;
    // we ignore the port for now
    uint32_t port;
    uint8_t addr_type;
    oai::utils::fqdn::resolve(host, ip_address, port, addr_type);
    if (addr_type != 0) {
      // TODO:
      throw std::invalid_argument(fmt::format(
          "IPv6 is not supported at the moment. Please provide a valid IPv4 "
          "address in your DNS configuration for the host {}.",
          host));
    }
    return oai::utils::conv::fromString(ip_address);
  }
  return oai::utils::conv::fromString(host);
}

//------------------------------------------------------------------------------
void upf_config_yaml::to_upf_config(upf_config& cfg) {
  std::shared_ptr<upf> upf_local = std::static_pointer_cast<upf>(get_local());
  cfg.instance                   = upf_local->get_instance_id();
  cfg.log_level                  = spdlog::level::from_str(log_level());
  cfg.register_nrf               = register_nrf();
  cfg.http_request_timeout       = get_http_request_timeout();

  std::string remote_n6_addr;
  uint8_t addr_type = {};
  unsigned int port = 0;
  oai::utils::fqdn::resolve(
      upf_local->get_remote_n6(), remote_n6_addr, port, addr_type);
  if (addr_type != 0) {  // IPv6: TODO
    throw("DO NOT SUPPORT IPV6 ADDR FOR NRF!");
  } else {  // IPv4
    IPV4_STR_ADDR_TO_INADDR(
        oai::utils::trim(remote_n6_addr).c_str(), cfg.remote_n6,
        "BAD IPv4 ADDRESS FORMAT FOR N6 DN !");
  }

  if (!cfg.register_nrf) {
    std::vector<string_config_value> smf_list = upf_local->get_smf_list();
    for (const auto& smf_host : smf_list) {
      std::string smf_addr;
      uint8_t addr_type = {};
      pfcp::node_id_t n = {};
      unsigned int port = 0;
      n.node_id_type    = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;  // actually
      oai::utils::fqdn::resolve(
          smf_host.get_value(), smf_addr, port, addr_type);
      if (addr_type != 0) {  // IPv6: TODO
        throw("DO NOT SUPPORT IPV6 ADDR FOR SMF!");
      } else {  // IPv4
        IPV4_STR_ADDR_TO_INADDR(
            oai::utils::trim(smf_addr).c_str(), n.u1.ipv4_address,
            "BAD IPv4 ADDRESS FORMAT FOR SMF !");
      }
      cfg.smfs.push_back(n);
    }
  }

  if (get_nf(NRF_CONFIG_NAME)->is_set() & register_nrf()) {
    cfg.nrf_addr = get_nf(NRF_CONFIG_NAME)->get_sbi();
  }

  cfg.http_version = get_http_version();

  cfg.sbi.port    = local().get_sbi().get_port();
  cfg.sbi.addr4   = local().get_sbi().get_addr4();
  cfg.sbi.if_name = local().get_sbi().get_if_name();

  // Feature flags - Performance
  cfg.enable_bpf_datapath =
      upf_local->get_support_features().get_option_enable_bpf_datapath();

  // Feature flags - PFCP Rules
  cfg.enable_qos = upf_local->get_support_features().get_option_enable_qos();
  cfg.enable_urr = upf_local->get_support_features().get_option_enable_urr();
  cfg.enable_bar = upf_local->get_support_features().get_option_enable_bar();
  cfg.enable_mar = upf_local->get_support_features().get_option_enable_mar();

  // Feature flags - Network Features
  cfg.enable_snat = upf_local->get_support_features().get_option_enable_snat();
  cfg.enable_fr   = upf_local->get_support_features().get_option_enable_fr();
  cfg.enable_eth_pdu =
      upf_local->get_support_features().get_option_enable_eth_pdu();

  // ==========================================================================
  // Datapath Configuration Transfer
  // Transfer values from upf_datapath_configuration to upf_config
  // ==========================================================================

  const upf_datapath_configuration& datapath_cfg =
      upf_local->get_datapath_configuration();

  cfg.max_pdu_sessions =
      static_cast<uint32_t>(datapath_cfg.get_max_pdu_sessions());
  cfg.max_upf_interfaces =
      static_cast<uint16_t>(datapath_cfg.get_max_upf_interfaces());
  cfg.max_upf_redirect_interfaces =
      static_cast<uint16_t>(datapath_cfg.get_max_upf_redirect_interfaces());
  cfg.max_pdrs_per_pdu_session =
      static_cast<uint16_t>(datapath_cfg.get_max_pdrs_per_pdu_session());
  cfg.max_fars_per_pdu_session =
      static_cast<uint16_t>(datapath_cfg.get_max_fars_per_pdu_session());
  cfg.max_qers_per_pdu_session =
      static_cast<uint16_t>(datapath_cfg.get_max_qers_per_pdu_session());
  cfg.max_urrs_per_pdu_session =
      static_cast<uint16_t>(datapath_cfg.get_max_urrs_per_pdu_session());
  cfg.max_bars_per_pdu_session =
      static_cast<uint16_t>(datapath_cfg.get_max_bars_per_pdu_session());
  cfg.max_sdf_filters_per_pdu_session =
      static_cast<uint16_t>(datapath_cfg.get_max_sdf_filters_per_pdu_session());
  cfg.max_sdf_filter_string_length =
      static_cast<uint16_t>(datapath_cfg.get_max_sdf_filter_string_length());
  cfg.max_arp_entries =
      static_cast<uint16_t>(datapath_cfg.get_max_arp_entries());
  cfg.max_application_ids_per_session =
      static_cast<uint16_t>(datapath_cfg.get_max_application_ids_per_session());
  cfg.max_traffic_endpoints_per_session = static_cast<uint16_t>(
      datapath_cfg.get_max_traffic_endpoints_per_session());
  cfg.max_ethernet_packet_filters_per_session = static_cast<uint16_t>(
      datapath_cfg.get_max_ethernet_packet_filters_per_session());
  cfg.max_redundant_transmission_params_per_session = static_cast<uint16_t>(
      datapath_cfg.get_max_redundant_transmission_params_per_session());

  logger::logger_registry::get_logger(LOGGER_NAME)
      .info(
          "Datapath configuration transferred: max_pdu_sessions=%u, "
          "max_upf_interfaces=%u, max_arp_entries=%u",
          cfg.max_pdu_sessions, cfg.max_upf_interfaces, cfg.max_arp_entries);

  auto snssai_upf_list = upf_local->get_upf_info().getSNssaiUpfInfoList();
  for (const auto& snssai : snssai_upf_list) {
    snssai_upf_info_item_t item;
    item.snssai.sd  = snssai.getSNssai().getSd();
    item.snssai.sst = snssai.getSNssai().getSst();
    for (const auto& dnn : snssai.getDnnUpfInfoList()) {
      dnn_upf_info_item_t dnn_item = {};
      dnn_item.dnn                 = dnn.getDnn();
      item.dnn_upf_info_list.insert(dnn_item);
    }
    cfg.upf_info.snssai_upf_info_list.push_back(item);
  }

  // ToDo: Remove hardcoded pdn value here
  for (const auto& cfg_dnn : get_dnns()) {
    pdn_cfg_t pdn_cfg = {};
    unsigned char buf_in_addr[sizeof(struct in_addr) + 1];
    inet_pton(AF_INET, inet_ntoa(cfg_dnn.get_ipv4_subnet()), buf_in_addr);
    memcpy(&pdn_cfg.network_ipv4, buf_in_addr, sizeof(struct in_addr));
    pdn_cfg.prefix_ipv4          = cfg_dnn.get_ipv4_subnet_prefix();
    pdn_cfg.network_ipv4_be      = htobe32(pdn_cfg.network_ipv4.s_addr);
    pdn_cfg.network_mask_ipv4    = 0xFFFFFFFF << (32 - pdn_cfg.prefix_ipv4);
    pdn_cfg.network_mask_ipv4_be = htobe32(pdn_cfg.network_mask_ipv4);
    logger::logger_registry::get_logger(LOGGER_NAME)
        .debug(
            "PDN Network validation for UE Subnet:  %s ",
            oai::utils::conv::toString(cfg_dnn.get_ipv4_subnet()));
    logger::logger_registry::get_logger(LOGGER_NAME)
        .debug(
            "IP Pool :  %s - %s",
            oai::utils::conv::toString(cfg_dnn.get_ipv4_pool_start()),
            oai::utils::conv::toString(cfg_dnn.get_ipv4_pool_end()));
    cfg.pdns.push_back(pdn_cfg);
  }

  // we set the local interfaces and also the UPF profile
  for (const auto& iface : upf_local->get_interfaces()) {
    if (iface.first == UPF_CONFIG_N3_LABEL) {
      cfg.n3 = iface.second.to_interface_config();
    } else if (iface.first == UPF_CONFIG_N6_LABEL) {
      cfg.n6 = iface.second.to_interface_config();
    } else if (iface.first == UPF_CONFIG_N4_LABEL) {
      cfg.n4 = iface.second.to_interface_config();
    }
    cfg.upf_info.interface_upf_info_list.push_back(
        iface.second.to_upf_info_item());
  }

  if (get_nf(oai::config::SMF_CONFIG_NAME)) {
    cfg.smf_addr.api_version = get_nf("smf")->get_sbi().get_api_version();
    cfg.smf_addr.uri_root    = get_nf(oai::config::SMF_CONFIG_NAME)->get_url();
  }

  for (int i = 0; i < m_dnns.size(); i++) {
    bool m_dnn_matched = false;
    for (auto s : cfg.upf_info.snssai_upf_info_list) {
      for (auto d : s.dnn_upf_info_list) {
        if (d.dnn == m_dnns[i].get_dnn()) m_dnn_matched = true;
      }
    }
    if (!m_dnn_matched) m_dnns[i].unset_config();
  }
}

upf_interface_config upf_config_yaml::get_default_n3_interface() {
  return upf_interface_config(
      "N3", "oai-upf", 2152, "eth0", UPF_CONFIG_N3_LABEL, "access.oai.org");
}

upf_interface_config upf_config_yaml::get_default_n4_interface() {
  return upf_interface_config(
      "N4", "oai-upf", 8805, "eth0", UPF_CONFIG_N4_LABEL);
}

upf_interface_config upf_config_yaml::get_default_n6_interface() {
  return upf_interface_config(
      "N6", "oai-upf", 2152, "eth0", UPF_CONFIG_N6_LABEL, "core.oai.org");
}

upf_interface_config::upf_interface_config(
    const std::string& name, const std::string& host, uint16_t port,
    const std::string& if_name, const std::string& if_type)
    : upf_interface_config(name, host, port, if_name, if_type, ""){};

upf_interface_config::upf_interface_config(
    const std::string& name, const std::string& host, uint16_t port,
    const std::string& if_name, const std::string& if_type,
    const std::string& nwi)
    : local_interface(name, host, port, if_name) {
  set_if_type(if_type);
  m_nwi = string_config_value("Network Instance", nwi);
}

void upf_interface_config::from_yaml(const YAML::Node& node) {
  local_interface::from_yaml(node);
  if (node["nwi"]) {
    m_nwi.from_yaml(node["nwi"]);
  }
}

void upf_interface_config::set_if_type(const std::string& if_type) {
  m_interface_type = string_config_value("Interface Type", if_type);
}

std::string upf_interface_config::to_string(const std::string& indent) const {
  std::string out          = local_interface::to_string(indent);
  unsigned int inner_width = get_inner_width(indent.length());

  if (!m_nwi.get_value().empty()) {
    out.append(indent).append(fmt::format(
        BASE_FORMATTER, INNER_LIST_ELEM, m_nwi.get_config_name(), inner_width,
        m_nwi.get_value()));
  }
  return out;
}

interface_upf_info_item_t upf_interface_config::to_upf_info_item() const {
  interface_upf_info_item_t item{};
  item.endpoint_fqdn  = m_host.get_value();
  item.interface_type = m_interface_type.get_value();
  item.ipv4_addresses = std::vector<struct in_addr>{m_addr4};
  // TODO commented out because we should not send IPv6 to NRF if we do not
  // support it
  // item.ipv6_addresses = std::vector<struct in6_addr>{m_addr6};

  return item;
}
interface_cfg_t upf_interface_config::to_interface_config() const {
  // TODO this method is only temporary until we refactor the whole config
  interface_cfg_t cfg;
  cfg.addr4   = get_addr4();
  cfg.addr6   = get_addr6();
  cfg.mtu     = get_mtu();
  cfg.port    = get_port();
  cfg.if_name = get_if_name();

  return cfg;
}

//==============================================================================
// UPF BPF Map Configuration Implementation
// Complete 5-Layer Validation Architecture
//==============================================================================
//------------------------------------------------------------------------------
const upf_datapath_configuration& upf::get_datapath_configuration() const {
  return m_upf_datapath_configuration;
}

upf_datapath_configuration::upf_datapath_configuration(
    const std::string& name) {
  m_config_name = name;
  m_set         = false;

  // Initialize with defaults and validation intervals
  // Based on 3GPP TS 29.244 PFCP specification

  // PFCP Session Limits (Section 7.2.2 - CP F-SEID)
  m_max_pdu_sessions =
      int_config_value(UPF_MAX_PDU_SESSIONS, UPF_DEFAULT_MAX_PDU_SESSIONS);
  m_max_pdu_sessions.set_validation_interval(1, 100000);

  // PDR Limits (Section 7.5.2.2 - Packet Detection Rule)
  m_max_pdrs_per_pdu_session = int_config_value(
      UPF_MAX_PDRS_PER_PDU_SESSION, UPF_DEFAULT_MAX_PDRS_PER_PDU_SESSION);
  m_max_pdrs_per_pdu_session.set_validation_interval(1, 64);

  // FAR Limits (Section 7.5.2.3 - Forwarding Action Rule)
  m_max_fars_per_pdu_session = int_config_value(
      UPF_MAX_FARS_PER_PDU_SESSION, UPF_DEFAULT_MAX_FARS_PER_PDU_SESSION);
  m_max_fars_per_pdu_session.set_validation_interval(1, 64);

  // QER Limits (Section 7.5.2.4 - QoS Enforcement Rule)
  m_max_qers_per_pdu_session = int_config_value(
      UPF_MAX_QERS_PER_PDU_SESSION, UPF_DEFAULT_MAX_QERS_PER_PDU_SESSION);
  m_max_qers_per_pdu_session.set_validation_interval(1, 32);

  // URR Limits (Section 7.5.2.5 - Usage Reporting Rule)
  m_max_urrs_per_pdu_session = int_config_value(
      UPF_MAX_URRS_PER_PDU_SESSION, UPF_DEFAULT_MAX_URRS_PER_PDU_SESSION);
  m_max_urrs_per_pdu_session.set_validation_interval(0, 16);

  // BAR Limits (Section 7.5.2.6 - Buffering Action Rule)
  m_max_bars_per_pdu_session = int_config_value(
      UPF_MAX_BARS_PER_PDU_SESSION, UPF_DEFAULT_MAX_BARS_PER_PDU_SESSION);
  m_max_bars_per_pdu_session.set_validation_interval(0, 8);

  // SDF Filter Limits (Table 7.5.2.2-2)
  m_max_sdf_filters_per_pdu_session = int_config_value(
      UPF_MAX_SDF_FILTERS_PER_PDU_SESSION,
      UPF_DEFAULT_MAX_SDF_FILTERS_PER_PDU_SESSION);
  m_max_sdf_filters_per_pdu_session.set_validation_interval(1, 32);

  // SDF Filter String Length
  m_max_sdf_filter_string_length = int_config_value(
      UPF_MAX_SDF_FILTER_STRING_LENGTH,
      UPF_DEFAULT_MAX_SDF_FILTER_STRING_LENGTH);
  m_max_sdf_filter_string_length.set_validation_interval(64, 2048);

  // Network Interfaces
  m_max_upf_interfaces =
      int_config_value(UPF_MAX_UPF_INTERFACES, UPF_DEFAULT_MAX_UPF_INTERFACES);
  m_max_upf_interfaces.set_validation_interval(2, 16);

  m_max_upf_redirect_interfaces = int_config_value(
      UPF_MAX_UPF_REDIRECT_INTERFACES, UPF_DEFAULT_MAX_UPF_REDIRECT_INTERFACES);
  m_max_upf_redirect_interfaces.set_validation_interval(1, 16);

  // ARP Entries
  m_max_arp_entries =
      int_config_value(UPF_MAX_ARP_ENTRIES, UPF_DEFAULT_MAX_ARP_ENTRIES);
  m_max_arp_entries.set_validation_interval(2, 4096);

  // Advanced Features
  m_max_application_ids_per_session = int_config_value(
      UPF_MAX_APPLICATION_IDS_PER_SESSION,
      UPF_DEFAULT_MAX_APPLICATION_IDS_PER_SESSION);
  m_max_application_ids_per_session.set_validation_interval(0, 32);

  m_max_traffic_endpoints_per_session = int_config_value(
      UPF_MAX_TRAFFIC_ENDPOINTS_PER_SESSION,
      UPF_DEFAULT_MAX_TRAFFIC_ENDPOINTS_PER_SESSION);
  m_max_traffic_endpoints_per_session.set_validation_interval(1, 4);

  m_max_ethernet_packet_filters_per_session = int_config_value(
      UPF_MAX_ETHERNET_PACKET_FILTERS_PER_SESSION,
      UPF_DEFAULT_MAX_ETHERNET_PACKET_FILTERS_PER_SESSION);
  m_max_ethernet_packet_filters_per_session.set_validation_interval(0, 16);

  m_max_redundant_transmission_params_per_session = int_config_value(
      UPF_MAX_REDUNDANT_TRANSMISSION_PARAMS_PER_SESSION,
      UPF_DEFAULT_MAX_REDUNDANT_TRANSMISSION_PARAMS_PER_SESSION);
  m_max_redundant_transmission_params_per_session.set_validation_interval(0, 4);
}

void upf_datapath_configuration::from_yaml(const YAML::Node& node) {
  if (node[UPF_MAX_PDU_SESSIONS]) {
    m_max_pdu_sessions.from_yaml(node[UPF_MAX_PDU_SESSIONS]);
  }
  if (node[UPF_MAX_PDRS_PER_PDU_SESSION]) {
    m_max_pdrs_per_pdu_session.from_yaml(node[UPF_MAX_PDRS_PER_PDU_SESSION]);
  }
  if (node[UPF_MAX_FARS_PER_PDU_SESSION]) {
    m_max_fars_per_pdu_session.from_yaml(node[UPF_MAX_FARS_PER_PDU_SESSION]);
  }
  if (node[UPF_MAX_QERS_PER_PDU_SESSION]) {
    m_max_qers_per_pdu_session.from_yaml(node[UPF_MAX_QERS_PER_PDU_SESSION]);
  }
  if (node[UPF_MAX_URRS_PER_PDU_SESSION]) {
    m_max_urrs_per_pdu_session.from_yaml(node[UPF_MAX_URRS_PER_PDU_SESSION]);
  }
  if (node[UPF_MAX_BARS_PER_PDU_SESSION]) {
    m_max_bars_per_pdu_session.from_yaml(node[UPF_MAX_BARS_PER_PDU_SESSION]);
  }
  if (node[UPF_MAX_SDF_FILTERS_PER_PDU_SESSION]) {
    m_max_sdf_filters_per_pdu_session.from_yaml(
        node[UPF_MAX_SDF_FILTERS_PER_PDU_SESSION]);
  }
  if (node[UPF_MAX_SDF_FILTER_STRING_LENGTH]) {
    m_max_sdf_filter_string_length.from_yaml(
        node[UPF_MAX_SDF_FILTER_STRING_LENGTH]);
  }
  if (node[UPF_MAX_UPF_INTERFACES]) {
    m_max_upf_interfaces.from_yaml(node[UPF_MAX_UPF_INTERFACES]);
  }
  if (node[UPF_MAX_UPF_REDIRECT_INTERFACES]) {
    m_max_upf_redirect_interfaces.from_yaml(
        node[UPF_MAX_UPF_REDIRECT_INTERFACES]);
  }
  if (node[UPF_MAX_ARP_ENTRIES]) {
    m_max_arp_entries.from_yaml(node[UPF_MAX_ARP_ENTRIES]);
  }
  if (node[UPF_MAX_APPLICATION_IDS_PER_SESSION]) {
    m_max_application_ids_per_session.from_yaml(
        node[UPF_MAX_APPLICATION_IDS_PER_SESSION]);
  }
  if (node[UPF_MAX_TRAFFIC_ENDPOINTS_PER_SESSION]) {
    m_max_traffic_endpoints_per_session.from_yaml(
        node[UPF_MAX_TRAFFIC_ENDPOINTS_PER_SESSION]);
  }
  if (node[UPF_MAX_ETHERNET_PACKET_FILTERS_PER_SESSION]) {
    m_max_ethernet_packet_filters_per_session.from_yaml(
        node[UPF_MAX_ETHERNET_PACKET_FILTERS_PER_SESSION]);
  }
  if (node[UPF_MAX_REDUNDANT_TRANSMISSION_PARAMS_PER_SESSION]) {
    m_max_redundant_transmission_params_per_session.from_yaml(
        node[UPF_MAX_REDUNDANT_TRANSMISSION_PARAMS_PER_SESSION]);
  }
  m_set = true;
}

nlohmann::json upf_datapath_configuration::to_json() {
  nlohmann::json json_data;
  json_data[UPF_MAX_PDU_SESSIONS] = m_max_pdu_sessions.to_json();
  json_data[UPF_MAX_PDRS_PER_PDU_SESSION] =
      m_max_pdrs_per_pdu_session.to_json();
  json_data[UPF_MAX_FARS_PER_PDU_SESSION] =
      m_max_fars_per_pdu_session.to_json();
  json_data[UPF_MAX_QERS_PER_PDU_SESSION] =
      m_max_qers_per_pdu_session.to_json();
  json_data[UPF_MAX_URRS_PER_PDU_SESSION] =
      m_max_urrs_per_pdu_session.to_json();
  json_data[UPF_MAX_BARS_PER_PDU_SESSION] =
      m_max_bars_per_pdu_session.to_json();
  json_data[UPF_MAX_SDF_FILTERS_PER_PDU_SESSION] =
      m_max_sdf_filters_per_pdu_session.to_json();
  json_data[UPF_MAX_SDF_FILTER_STRING_LENGTH] =
      m_max_sdf_filter_string_length.to_json();
  json_data[UPF_MAX_UPF_INTERFACES] = m_max_upf_interfaces.to_json();
  json_data[UPF_MAX_UPF_REDIRECT_INTERFACES] =
      m_max_upf_redirect_interfaces.to_json();
  json_data[UPF_MAX_ARP_ENTRIES] = m_max_arp_entries.to_json();
  json_data[UPF_MAX_APPLICATION_IDS_PER_SESSION] =
      m_max_application_ids_per_session.to_json();
  json_data[UPF_MAX_TRAFFIC_ENDPOINTS_PER_SESSION] =
      m_max_traffic_endpoints_per_session.to_json();
  json_data[UPF_MAX_ETHERNET_PACKET_FILTERS_PER_SESSION] =
      m_max_ethernet_packet_filters_per_session.to_json();
  json_data[UPF_MAX_REDUNDANT_TRANSMISSION_PARAMS_PER_SESSION] =
      m_max_redundant_transmission_params_per_session.to_json();
  return json_data;
}

bool upf_datapath_configuration::from_json(const nlohmann::json& json_data) {
  try {
    if (json_data.contains(UPF_MAX_PDU_SESSIONS)) {
      m_max_pdu_sessions.from_json(json_data[UPF_MAX_PDU_SESSIONS]);
    }
    if (json_data.contains(UPF_MAX_PDRS_PER_PDU_SESSION)) {
      m_max_pdrs_per_pdu_session.from_json(
          json_data[UPF_MAX_PDRS_PER_PDU_SESSION]);
    }
    if (json_data.contains(UPF_MAX_FARS_PER_PDU_SESSION)) {
      m_max_fars_per_pdu_session.from_json(
          json_data[UPF_MAX_FARS_PER_PDU_SESSION]);
    }
    if (json_data.contains(UPF_MAX_QERS_PER_PDU_SESSION)) {
      m_max_qers_per_pdu_session.from_json(
          json_data[UPF_MAX_QERS_PER_PDU_SESSION]);
    }
    if (json_data.contains(UPF_MAX_URRS_PER_PDU_SESSION)) {
      m_max_urrs_per_pdu_session.from_json(
          json_data[UPF_MAX_URRS_PER_PDU_SESSION]);
    }
    if (json_data.contains(UPF_MAX_BARS_PER_PDU_SESSION)) {
      m_max_bars_per_pdu_session.from_json(
          json_data[UPF_MAX_BARS_PER_PDU_SESSION]);
    }
    if (json_data.contains(UPF_MAX_SDF_FILTERS_PER_PDU_SESSION)) {
      m_max_sdf_filters_per_pdu_session.from_json(
          json_data[UPF_MAX_SDF_FILTERS_PER_PDU_SESSION]);
    }
    if (json_data.contains(UPF_MAX_SDF_FILTER_STRING_LENGTH)) {
      m_max_sdf_filter_string_length.from_json(
          json_data[UPF_MAX_SDF_FILTER_STRING_LENGTH]);
    }
    if (json_data.contains(UPF_MAX_UPF_INTERFACES)) {
      m_max_upf_interfaces.from_json(json_data[UPF_MAX_UPF_INTERFACES]);
    }
    if (json_data.contains(UPF_MAX_UPF_REDIRECT_INTERFACES)) {
      m_max_upf_redirect_interfaces.from_json(
          json_data[UPF_MAX_UPF_REDIRECT_INTERFACES]);
    }
    if (json_data.contains(UPF_MAX_ARP_ENTRIES)) {
      m_max_arp_entries.from_json(json_data[UPF_MAX_ARP_ENTRIES]);
    }
    if (json_data.contains(UPF_MAX_APPLICATION_IDS_PER_SESSION)) {
      m_max_application_ids_per_session.from_json(
          json_data[UPF_MAX_APPLICATION_IDS_PER_SESSION]);
    }
    if (json_data.contains(UPF_MAX_TRAFFIC_ENDPOINTS_PER_SESSION)) {
      m_max_traffic_endpoints_per_session.from_json(
          json_data[UPF_MAX_TRAFFIC_ENDPOINTS_PER_SESSION]);
    }
    if (json_data.contains(UPF_MAX_ETHERNET_PACKET_FILTERS_PER_SESSION)) {
      m_max_ethernet_packet_filters_per_session.from_json(
          json_data[UPF_MAX_ETHERNET_PACKET_FILTERS_PER_SESSION]);
    }
    if (json_data.contains(UPF_MAX_REDUNDANT_TRANSMISSION_PARAMS_PER_SESSION)) {
      m_max_redundant_transmission_params_per_session.from_json(
          json_data[UPF_MAX_REDUNDANT_TRANSMISSION_PARAMS_PER_SESSION]);
    }
    m_set = true;
    return true;
  } catch (nlohmann::detail::exception& e) {
    return false;
  } catch (std::exception& e) {
    return false;
  }
}

std::string upf_datapath_configuration::to_string(
    const std::string& indent) const {
  if (!m_set) return "";

  std::string out;
  std::string inner_indent = add_indent(indent);
  unsigned int inner_width = get_inner_width(inner_indent.length());

  out.append(indent).append(
      fmt::format("{} {}:\n", OUTER_LIST_ELEM, "Datapath Configuration"));

  // PFCP Session Limits
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max PFCP Sessions", inner_width,
          m_max_pdu_sessions.to_string("")));

  // Rule Limits per PDU Session
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max PDRs per Session", inner_width,
          m_max_pdrs_per_pdu_session.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max FARs per Session", inner_width,
          m_max_fars_per_pdu_session.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max QERs per Session", inner_width,
          m_max_qers_per_pdu_session.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max URRs per Session", inner_width,
          m_max_urrs_per_pdu_session.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max BARs per Session", inner_width,
          m_max_bars_per_pdu_session.to_string("")));

  // SDF Filters
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max SDF Filters per Session",
          inner_width, m_max_sdf_filters_per_pdu_session.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max SDF Filter String Length",
          inner_width, m_max_sdf_filter_string_length.to_string("")));

  // Network Configuration
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max UPF Interfaces", inner_width,
          m_max_upf_interfaces.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max Redirect Interfaces",
          inner_width, m_max_upf_redirect_interfaces.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max ARP Entries", inner_width,
          m_max_arp_entries.to_string("")));

  // Advanced Features
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max Application IDs per Session",
          inner_width, m_max_application_ids_per_session.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM, "Max Traffic Endpoints per Session",
          inner_width, m_max_traffic_endpoints_per_session.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM,
          "Max Ethernet Packet Filters per Session", inner_width,
          m_max_ethernet_packet_filters_per_session.to_string("")));
  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, INNER_LIST_ELEM,
          "Max Redundant Transmission Params per Session", inner_width,
          m_max_redundant_transmission_params_per_session.to_string("")));

  return out;
}

void upf_datapath_configuration::validate() {
  if (!m_set) return;

  logger::logger_registry::get_logger(LOGGER_NAME)
      .info("Validating UPF datapath configuration...");

  //============================================================================
  // LAYER 1: Basic Range Validation (15 rules)
  //============================================================================
  m_max_pdu_sessions.validate();
  m_max_pdrs_per_pdu_session.validate();
  m_max_fars_per_pdu_session.validate();
  m_max_qers_per_pdu_session.validate();
  m_max_urrs_per_pdu_session.validate();
  m_max_bars_per_pdu_session.validate();
  m_max_sdf_filters_per_pdu_session.validate();
  m_max_sdf_filter_string_length.validate();
  m_max_upf_interfaces.validate();
  m_max_upf_redirect_interfaces.validate();
  m_max_arp_entries.validate();
  m_max_application_ids_per_session.validate();
  m_max_traffic_endpoints_per_session.validate();
  m_max_ethernet_packet_filters_per_session.validate();
  m_max_redundant_transmission_params_per_session.validate();

  //============================================================================
  // LAYER 2: Cross-Parameter Validation (5 rules)
  //============================================================================
  int max_pdrs     = m_max_pdrs_per_pdu_session.get_value();
  int max_fars     = m_max_fars_per_pdu_session.get_value();
  int max_qers     = m_max_qers_per_pdu_session.get_value();
  int max_urrs     = m_max_urrs_per_pdu_session.get_value();
  int max_upf_if   = m_max_upf_interfaces.get_value();
  int max_redirect = m_max_upf_redirect_interfaces.get_value();

  // Rule 2.1: Redirect interfaces must be <= total interfaces
  if (max_redirect > max_upf_if) {
    throw std::runtime_error(fmt::format(
        "max_upf_redirect_interfaces ({}) cannot exceed max_upf_interfaces "
        "({})",
        max_redirect, max_upf_if));
  }

  // Rule 2.2: FARs should equal PDRs (typical 1:1 mapping)
  if (max_fars != max_pdrs) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .warn(
            "max_fars_per_pdu_session ({}) does not equal "
            "max_pdrs_per_pdu_session ({}). "
            "Each PDR typically references exactly one FAR (3GPP TS 29.244 "
            "Section 7.5.2.2). "
            "This configuration is valid but unusual.",
            max_fars, max_pdrs);
  }

  // Rule 2.3: FARs must be >= PDRs (each PDR needs a FAR)
  if (max_fars < max_pdrs) {
    throw std::runtime_error(fmt::format(
        "max_fars_per_pdu_session ({}) cannot be less than "
        "max_pdrs_per_pdu_session ({}) "
        "because each PDR must reference at least one FAR (3GPP TS 29.244 "
        "Section 7.5.2.2)",
        max_fars, max_pdrs));
  }

  // Rule 2.4: QERs can be < PDRs (QERs are shared)
  if (max_qers > max_pdrs) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .warn(
            "max_qers_per_pdu_session ({}) exceeds max_pdrs_per_pdu_session "
            "({}). "
            "QERs are typically SHARED across multiple PDRs (3GPP TS 29.244 "
            "Section 7.5.2.4), "
            "so having more QERs than PDRs is unusual. This configuration is "
            "valid but may indicate misconfiguration.",
            max_qers, max_pdrs);
  }

  // Rule 2.5: URRs typically << PDRs (URRs are shared)
  if (max_urrs > max_pdrs) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .warn(
            "max_urrs_per_pdu_session ({}) exceeds max_pdrs_per_pdu_session "
            "({}). "
            "URRs are typically SHARED for charging/reporting across many PDRs "
            "(3GPP TS 29.244 Section 7.5.2.5), "
            "so this configuration is unusual. Consider if you need this many "
            "URRs.",
            max_urrs, max_pdrs);
  }

  //============================================================================
  // LAYER 3: Overflow Prevention (2 rules)
  //============================================================================
  int max_sessions = m_max_pdu_sessions.get_value();
  int max_sdfs     = m_max_sdf_filters_per_pdu_session.get_value();

  const int MAX_SAFE_MAP_SIZE = 1000000;  // 1 million entries

  // Rule 3.1: rules_match_pdr_map size check
  long long rules_pdr_map_size =
      static_cast<long long>(max_sessions) * max_pdrs;
  if (rules_pdr_map_size > MAX_SAFE_MAP_SIZE) {
    throw std::runtime_error(fmt::format(
        "Derived BPF map 'rules_match_pdr_map' size ({} = {} sessions × {} "
        "PDRs) "
        "exceeds maximum safe size ({}). Reduce max_pdu_sessions or "
        "max_pdrs_per_pdu_session.",
        rules_pdr_map_size, max_sessions, max_pdrs, MAX_SAFE_MAP_SIZE));
  }

  // Rule 3.2: sdf_filters_map size check
  long long sdf_map_size = static_cast<long long>(max_sessions) * max_sdfs;
  if (sdf_map_size > MAX_SAFE_MAP_SIZE) {
    throw std::runtime_error(fmt::format(
        "Derived BPF map 'sdf_filters_map' size ({} = {} sessions × {} "
        "filters) "
        "exceeds maximum safe size ({}). Reduce max_pdu_sessions or "
        "max_sdf_filters_per_pdu_session.",
        sdf_map_size, max_sessions, max_sdfs, MAX_SAFE_MAP_SIZE));
  }

  //============================================================================
  // LAYER 4: Memory Estimation (2 rules)
  //============================================================================
  int filter_len = m_max_sdf_filter_string_length.get_value();

  // Memory estimation formula (bytes per session)
  // Base overhead + PDRs + QERs + SDFs + FAR/URR/BAR overhead
  long long bytes_per_session =
      1024 +                             // Base overhead
      (max_pdrs * 256) +                 // PDR entries
      (max_qers * 128) +                 // QER entries
      (max_sdfs * (128 + filter_len)) +  // SDF filter entries + strings
      512;                               // FAR/URR/BAR overhead

  long long total_memory_bytes = bytes_per_session * max_sessions;
  double total_memory_mb       = total_memory_bytes / (1024.0 * 1024.0);

  logger::logger_registry::get_logger(LOGGER_NAME)
      .info(
          "Estimated BPF map memory usage: %d MB",
          static_cast<int>(total_memory_mb));

  // Rule 4.1: Warn if > 1GB
  if (total_memory_mb > 1024) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .warn(
            "Estimated BPF map memory usage (%d MB) exceeds 1GB. "
            "This is a large deployment. Ensure sufficient system resources.",
            static_cast<int>(total_memory_mb));
  }

  // Rule 4.2: Error if > 8GB
  if (total_memory_mb > 8192) {
    throw std::runtime_error(fmt::format(
        "Estimated BPF map memory usage (%d MB) exceeds 8GB. "
        "This configuration is unsafe. Reduce session count or per-session "
        "limits.",
        static_cast<int>(total_memory_mb)));
  }

  //============================================================================
  // LAYER 5: Deployment Size Validation (1 rule)
  //============================================================================

  // Rule 5.1: Warn if > 50K sessions (recommend multi-UPF deployment)
  if (max_sessions > 50000) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .warn(
            "max_pdu_sessions ({}) exceeds 50,000. For deployments of this "
            "scale, "
            "consider using multiple UPFs for redundancy, scalability, and "
            "geographic distribution. "
            "Operators typically deploy UPF pools rather than single large "
            "UPFs.",
            max_sessions);
  }

  logger::logger_registry::get_logger(LOGGER_NAME)
      .info("UPF configuration validation successful");
}

// Getter implementations
int upf_datapath_configuration::get_max_pdu_sessions() const {
  return m_max_pdu_sessions.get_value();
}

int upf_datapath_configuration::get_max_pdrs_per_pdu_session() const {
  return m_max_pdrs_per_pdu_session.get_value();
}

int upf_datapath_configuration::get_max_fars_per_pdu_session() const {
  return m_max_fars_per_pdu_session.get_value();
}

int upf_datapath_configuration::get_max_qers_per_pdu_session() const {
  return m_max_qers_per_pdu_session.get_value();
}

int upf_datapath_configuration::get_max_urrs_per_pdu_session() const {
  return m_max_urrs_per_pdu_session.get_value();
}

int upf_datapath_configuration::get_max_bars_per_pdu_session() const {
  return m_max_bars_per_pdu_session.get_value();
}

int upf_datapath_configuration::get_max_sdf_filters_per_pdu_session() const {
  return m_max_sdf_filters_per_pdu_session.get_value();
}

int upf_datapath_configuration::get_max_sdf_filter_string_length() const {
  return m_max_sdf_filter_string_length.get_value();
}

int upf_datapath_configuration::get_max_upf_interfaces() const {
  return m_max_upf_interfaces.get_value();
}

int upf_datapath_configuration::get_max_upf_redirect_interfaces() const {
  return m_max_upf_redirect_interfaces.get_value();
}

int upf_datapath_configuration::get_max_arp_entries() const {
  return m_max_arp_entries.get_value();
}

int upf_datapath_configuration::get_max_application_ids_per_session() const {
  return m_max_application_ids_per_session.get_value();
}

int upf_datapath_configuration::get_max_traffic_endpoints_per_session() const {
  return m_max_traffic_endpoints_per_session.get_value();
}

int upf_datapath_configuration::get_max_ethernet_packet_filters_per_session()
    const {
  return m_max_ethernet_packet_filters_per_session.get_value();
}

int upf_datapath_configuration::
    get_max_redundant_transmission_params_per_session() const {
  return m_max_redundant_transmission_params_per_session.get_value();
}

}  // namespace oai::config
