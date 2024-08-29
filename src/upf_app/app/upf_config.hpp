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

/*! \file upf_config.hpp
 * \brief
 * \author Lionel Gauthier
 * \company Eurecom
 * \email: lionel.gauthier@eurecom.fr
 */

#ifndef FILE_UPF_CONFIG_HPP_SEEN
#define FILE_UPF_CONFIG_HPP_SEEN

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include <config_types.hpp>
#include <libconfig.h++>
#include <mutex>
#include <string>

#include "3gpp_23.003.h"
#include "3gpp_29.244.h"
#include "3gpp_29.510.h"
#include "DnnUpfInfoItem.h"
#include "Snssai.h"
#include "gtpv1u.hpp"
#include "logger.hpp"
#include "pfcp.hpp"
#include "sbi_helper.hpp"
#include "thread_sched.hpp"

constexpr auto UPF_CONFIG_OPTION_YES_STR = "Yes";
constexpr auto UPF_CONFIG_OPTION_NO_STR  = "No";

const oai::model::common::Snssai DEFAULT_SNSSAI{1};
const std::vector<oai::model::nrf::DnnUpfInfoItem> DEFAULT_DNN_LIST = {
    oai::model::nrf::DnnUpfInfoItem("default")};
using namespace libconfig;
using namespace oai::common::sbi;

namespace oai::config {
typedef struct interface_cfg_s {
  std::string if_name;
  struct in_addr addr4;
  struct in_addr network4;
  struct in6_addr addr6;
  unsigned int mtu;
  unsigned int port;
  util::thread_sched_params thread_rd_sched_params;
} interface_cfg_t;

typedef struct pdn_cfg_s {
  struct in_addr network_ipv4;
  uint32_t network_ipv4_be;
  uint32_t network_mask_ipv4;
  uint32_t network_mask_ipv4_be;
  int prefix_ipv4;
  struct in6_addr network_ipv6;
  int prefix_ipv6;
} pdn_cfg_t;

typedef struct itti_cfg_s {
  util::thread_sched_params itti_timer_sched_params;
  util::thread_sched_params n3_sched_params;
  util::thread_sched_params n4_sched_params;
  util::thread_sched_params upf_app_sched_params;
  util::thread_sched_params async_cmd_sched_params;
} itti_cfg_t;

// Non standart features
typedef struct nsf_cfg_s {
  bool bypass_ul_pfcp_rules;
} nsf_cfg_t;
class upf_config {
 public:
  /* Reader/writer lock for this configuration */
  std::mutex m_rw_lock;
  std::string pid_dir;
  unsigned int instance;
  std::string fqdn;
  spdlog::level::level_enum log_level;
  interface_cfg_t n3;
  interface_cfg_t n6;
  interface_cfg_t n4;
  itti_cfg_t itti;
  nsf_cfg_t nsf;

  std::string gateway;

  uint32_t max_pfcp_sessions;

  typedef struct nf_addr_s {
    struct in_addr ipv4_addr;
    unsigned int port;
    std::string api_version;
    std::string fqdn;
    std::string uri_root;
    unsigned int http_version;

  } nf_addr;

  bool enable_snat;
  std::vector<pdn_cfg_t> pdns;
  std::vector<pfcp::node_id_t> smfs;

  bool enable_5g_features;
  bool enable_bpf_datapath;
  bool enable_qos;
  bool register_nrf;
  struct in_addr remote_n6;
  upf_info_t upf_info;

  unsigned int http_version;
  uint32_t http_request_timeout;

  nf_addr smf_addr;
  sbi_interface nrf_addr;
  interface_cfg_t sbi;

  upf_config()
      : m_rw_lock(),
        pid_dir(),
        instance(0),
        fqdn(),
        n3(),
        n6(),
        gateway(),
        n4(),
        itti(),
        pdns(),
        smfs(),
        max_pfcp_sessions(100),
        nsf(),
        enable_snat(false),
        nrf_addr() {
    itti.itti_timer_sched_params.sched_priority = 85;
    itti.n3_sched_params.sched_priority         = 84;
    itti.n4_sched_params.sched_priority         = 84;
    itti.upf_app_sched_params.sched_priority    = 84;
    itti.async_cmd_sched_params.sched_priority  = 84;

    n3.thread_rd_sched_params.sched_priority = 98;
    n3.port                                  = gtpv1u::default_port;

    n6.thread_rd_sched_params.sched_priority = 98;

    n4.thread_rd_sched_params.sched_priority = 95;
    n4.port                                  = pfcp::default_port;

    enable_5g_features  = true;
    enable_bpf_datapath = false;
    enable_qos          = false;
    register_nrf        = false;
    upf_info            = {};

    log_level            = spdlog::level::debug;
    http_version         = 2;
    http_request_timeout = oai::common::sbi::kNfDefaultHttpRequestTimeout;
  };

  void lock() { m_rw_lock.lock(); };
  void unlock() { m_rw_lock.unlock(); };
  int execute();
  int get_pfcp_node_id(pfcp::node_id_t& node_id);
  int get_pfcp_fseid(pfcp::fseid_t& fseid);
};
}  // namespace oai::config

#endif /* FILE_UPF_CONFIG_HPP_SEEN */
