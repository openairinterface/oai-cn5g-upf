/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "upf_config_yaml.hpp"

#include <boost/algorithm/string.hpp>
#include <regex>

#include "conversions.hpp"
#include "fqdn.hpp"
#include "logger.hpp"

namespace oai::config {

//------------------------------------------------------------------------------
upf_support_features::upf_support_features(
    bool enable_bpf_datapath, bool enable_qos, u_int16_t max_upf_interfaces,
    u_int16_t max_upf_redirect_interfaces, u_int16_t max_pdu_session,
    u_int16_t max_pdrs_per_pdu_session, u_int16_t max_qos_flows_per_pdu_session,
    u_int16_t max_sdf_filters_per_pdu_session, u_int16_t max_arp_entries,
    bool enable_snat, bool enable_fr, bool enable_eth_pdu,
    bool ignore_qfi_for_uplink) {
  m_config_name = "Supported Features";

  m_enable_bpf_datapath = option_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_BPF_LABEL, enable_bpf_datapath);

  m_enable_qos = option_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_QOS_LABEL, enable_qos);

  m_max_upf_interfaces = int_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_MAX_UPF_INTERFACES_LABEL,
      (int) max_upf_interfaces);

  m_max_upf_redirect_interfaces = int_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_MAX_UPF_REDIRECT_INTERFACES_LABEL,
      (int) max_upf_redirect_interfaces);

  m_max_pdu_session = int_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_MAX_PDU_SESSION_LABEL, (int) max_pdu_session);

  m_max_pdrs_per_pdu_session = int_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_MAX_PDRS_PER_PDU_SESSION_LABEL,
      (int) max_pdrs_per_pdu_session);

  m_max_qos_flows_per_pdu_session = int_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_MAX_QOS_FLOWS_PER_PDU_SESSION_LABEL,
      (int) max_qos_flows_per_pdu_session);

  m_max_sdf_filters_per_pdu_session = int_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_MAX_SDF_FILTERS_PER_PDU_SESSION_LABEL,
      (int) max_sdf_filters_per_pdu_session);

  m_max_arp_entries = int_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_MAX_ARP_ENTRIES_LABEL, (int) max_arp_entries);

  m_enable_snat = option_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_SNAT_LABEL, (int) enable_snat);
  m_enable_fr = option_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_FR, (int) enable_fr);
  m_enable_eth_pdu = option_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_ETH_PDU_LABEL, (int) enable_eth_pdu);
  m_ignore_qfi_for_uplink = option_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_IGNORE_QFI_FOR_UPLINK_LABEL,
      (int) ignore_qfi_for_uplink);
}

//------------------------------------------------------------------------------
void upf_support_features::from_yaml(const YAML::Node& node) {
  if (node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_BPF]) {
    m_enable_bpf_datapath.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_BPF]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_QOS]) {
    m_enable_qos.from_yaml(node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_QOS]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_MAX_UPF_INTERFACES]) {
    m_max_upf_interfaces.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_MAX_UPF_INTERFACES]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_MAX_UPF_REDIRECT_INTERFACES]) {
    m_max_upf_redirect_interfaces.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_MAX_UPF_REDIRECT_INTERFACES]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_MAX_PDU_SESSION]) {
    m_max_pdu_session.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_MAX_PDU_SESSION]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_MAX_PDRS_PER_PDU_SESSION]) {
    m_max_pdrs_per_pdu_session.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_MAX_PDRS_PER_PDU_SESSION]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_MAX_QOS_FLOWS_PER_PDU_SESSION]) {
    m_max_qos_flows_per_pdu_session.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_MAX_QOS_FLOWS_PER_PDU_SESSION]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_MAX_SDF_FILTERS_PER_PDU_SESSION]) {
    m_max_sdf_filters_per_pdu_session.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_MAX_SDF_FILTERS_PER_PDU_SESSION]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_MAX_ARP_ENTRIES]) {
    m_max_arp_entries.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_MAX_ARP_ENTRIES]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_SNAT]) {
    m_enable_snat.from_yaml(node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_SNAT]);
  }
  if (node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_FR])
    m_enable_fr.from_yaml(node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_FR]);
  if (node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_ETH_PDU]) {
    m_enable_eth_pdu.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_ETH_PDU]);
  }
  if (node[UPF_CONFIG_SUPPORT_FEATURES_IGNORE_QFI_FOR_UPLINK]) {
    m_ignore_qfi_for_uplink.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_IGNORE_QFI_FOR_UPLINK]);
  }
}

//------------------------------------------------------------------------------
std::string upf_support_features::to_string(const std::string& indent) const {
  std::string out;
  unsigned int inner_width = get_inner_width(indent.length());

  // Enable BPF
  std::string enable_bpf_datapath = m_enable_bpf_datapath.get_value() ?
                                        UPF_CONFIG_OPTION_YES_STR :
                                        UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_BPF_LABEL, inner_width,
      enable_bpf_datapath));

  // Enable QoS
  std::string enable_qos = m_enable_qos.get_value() ?
                               UPF_CONFIG_OPTION_YES_STR :
                               UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_QOS_LABEL, inner_width, enable_qos));

  u_int16_t max_upf_interfaces = m_max_upf_interfaces.get_value();
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_MAX_UPF_INTERFACES_LABEL, inner_width,
      max_upf_interfaces));

  u_int16_t max_upf_redirect_interfaces =
      m_max_upf_redirect_interfaces.get_value();
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_MAX_UPF_REDIRECT_INTERFACES_LABEL,
      inner_width, max_upf_redirect_interfaces));

  u_int16_t max_pdu_session = m_max_pdu_session.get_value();
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_MAX_PDU_SESSION_LABEL, inner_width,
      max_pdu_session));

  u_int16_t max_pdrs_per_pdu_session = m_max_pdrs_per_pdu_session.get_value();
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_MAX_PDRS_PER_PDU_SESSION_LABEL, inner_width,
      max_pdrs_per_pdu_session));

  u_int16_t max_qos_flows_per_pdu_session =
      m_max_qos_flows_per_pdu_session.get_value();
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_MAX_QOS_FLOWS_PER_PDU_SESSION_LABEL,
      inner_width, max_qos_flows_per_pdu_session));

  u_int16_t max_sdf_filters_per_pdu_session =
      m_max_sdf_filters_per_pdu_session.get_value();
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_MAX_SDF_FILTERS_PER_PDU_SESSION_LABEL,
      inner_width, max_sdf_filters_per_pdu_session));

  u_int16_t max_arp_entries = m_max_arp_entries.get_value();
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_MAX_ARP_ENTRIES_LABEL, inner_width,
      max_arp_entries));

  // Enable SNAT
  std::string enable_snat = m_enable_snat.get_value() ?
                                UPF_CONFIG_OPTION_YES_STR :
                                UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_SNAT_LABEL, inner_width, enable_snat));

  std::string enable_fr = m_enable_fr.get_value() ? UPF_CONFIG_OPTION_YES_STR :
                                                    UPF_CONFIG_OPTION_NO_STR;

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, UPF_CONFIG_SUPPORT_FEATURES_ENABLE_FR,
      inner_width, enable_fr));

  // Enable Ethernet PDU
  std::string enable_eth_pdu = m_enable_eth_pdu.get_value() ?
                                   UPF_CONFIG_OPTION_YES_STR :
                                   UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_ETH_PDU_LABEL, inner_width,
      enable_eth_pdu));

  // Ignore QFI for Uplink
  std::string ignore_qfi_for_uplink = m_ignore_qfi_for_uplink.get_value() ?
                                          UPF_CONFIG_OPTION_YES_STR :
                                          UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_IGNORE_QFI_FOR_UPLINK_LABEL, inner_width,
      ignore_qfi_for_uplink));
  return out;
}

//------------------------------------------------------------------------------
upf::upf(
    const std::string& name, const std::string& host, const sbi_interface& sbi,
    const std::map<std::string, upf_interface_config>& interfaces)
    : nf(name, host, sbi),
      m_upf_support_features(
          false, false, 3, 2, 10000, 8, 8, 8, 2, false, false, false, true),
      m_interfaces(interfaces) {
  model::nrf::SnssaiUpfInfoItem item;
  item.setSNssai(DEFAULT_SNSSAI);
  item.setDnnUpfInfoList(DEFAULT_DNN_LIST);
  m_upf_info.setSNssaiUpfInfoList(
      std::vector<oai::model::nrf::SnssaiUpfInfoItem>{item});
}

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
bool upf_support_features::get_option_enable_bpf_datapath() const {
  return m_enable_bpf_datapath.get_value();
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_qos() const {
  return m_enable_qos.get_value();
}

//------------------------------------------------------------------------------
u_int16_t upf_support_features::get_option_max_upf_interfaces() const {
  return m_max_upf_interfaces.get_value();
}

//------------------------------------------------------------------------------
u_int16_t upf_support_features::get_option_max_upf_redirect_interfaces() const {
  return m_max_upf_redirect_interfaces.get_value();
}

//------------------------------------------------------------------------------
u_int16_t upf_support_features::get_option_max_pdu_session() const {
  return m_max_pdu_session.get_value();
}

//------------------------------------------------------------------------------
u_int16_t upf_support_features::get_option_max_pdrs_per_pdu_session() const {
  return m_max_pdrs_per_pdu_session.get_value();
}

//------------------------------------------------------------------------------
u_int16_t upf_support_features::get_option_max_qos_flows_per_pdu_session()
    const {
  return m_max_qos_flows_per_pdu_session.get_value();
}

//------------------------------------------------------------------------------
u_int16_t upf_support_features::get_option_max_sdf_filters_per_pdu_session()
    const {
  return m_max_sdf_filters_per_pdu_session.get_value();
}

//------------------------------------------------------------------------------
u_int16_t upf_support_features::get_option_max_arp_entries() const {
  return m_max_arp_entries.get_value();
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_snat() const {
  return m_enable_snat.get_value();
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
bool upf_support_features::get_option_ignore_qfi_for_uplink() const {
  return m_ignore_qfi_for_uplink.get_value();
}

//------------------------------------------------------------------------------
const upf_support_features& upf::get_support_features() const {
  return m_upf_support_features;
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

  cfg.enable_bpf_datapath =
      upf_local->get_support_features().get_option_enable_bpf_datapath();
  cfg.enable_qos = upf_local->get_support_features().get_option_enable_qos();

  cfg.max_upf_interfaces =
      upf_local->get_support_features().get_option_max_upf_interfaces();
  cfg.max_upf_redirect_interfaces =
      upf_local->get_support_features()
          .get_option_max_upf_redirect_interfaces();
  cfg.max_pdu_session =
      upf_local->get_support_features().get_option_max_pdu_session();
  cfg.max_pdrs_per_pdu_session =
      upf_local->get_support_features().get_option_max_pdrs_per_pdu_session();
  cfg.max_qos_flows_per_pdu_session =
      upf_local->get_support_features()
          .get_option_max_qos_flows_per_pdu_session();
  cfg.max_sdf_filters_per_pdu_session =
      upf_local->get_support_features()
          .get_option_max_sdf_filters_per_pdu_session();
  cfg.max_arp_entries =
      upf_local->get_support_features().get_option_max_arp_entries();

  cfg.enable_snat = upf_local->get_support_features().get_option_enable_snat();
  cfg.enable_fr   = upf_local->get_support_features().get_option_enable_fr();
  cfg.enable_eth_pdu =
      upf_local->get_support_features().get_option_enable_eth_pdu();
  cfg.ignore_qfi_for_uplink =
      upf_local->get_support_features().get_option_ignore_qfi_for_uplink();

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

}  // namespace oai::config
