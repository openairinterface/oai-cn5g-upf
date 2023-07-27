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

#ifndef FILE_3GPP_29_510_NRF_SEEN
#define FILE_3GPP_29_510_NRF_SEEN

#include <vector>
#include <nlohmann/json.hpp>
#include <boost/algorithm/string.hpp>
#include <map>
#include <unordered_set>

const uint32_t SD_NO_VALUE               = 0xFFFFFF;
const std::string SD_NO_VALUE_STR        = "0xFFFFFF";
const uint8_t SST_MAX_STANDARDIZED_VALUE = 127;

// Section 28.4, TS23.003
typedef struct s_nssai  // section 28.4, TS23.003
{
  const uint8_t HASH_SEED   = 17;
  const uint8_t HASH_FACTOR = 31;

  uint8_t sst;
  uint32_t sd;
  s_nssai(const uint8_t& m_sst, const uint32_t m_sd) : sst(m_sst), sd(m_sd) {}
  s_nssai(const uint8_t& m_sst, const std::string m_sd) : sst(m_sst) {
    sd = SD_NO_VALUE;
    if (m_sd.empty()) return;
    uint8_t base = 10;
    try {
      if (m_sd.size() > 2) {
        if (boost::iequals(m_sd.substr(0, 2), "0x")) {
          base = 16;
        }
      }
      sd = std::stoul(m_sd, nullptr, base);
    } catch (const std::exception& e) {
      Logger::upf_app().error(
          "Error when converting from string to int for S-NSSAI SD, error: %s",
          e.what());
      sd = SD_NO_VALUE;
    }
  }
  s_nssai() : sst(), sd() {}
  s_nssai(const s_nssai& p) : sst(p.sst), sd(p.sd) {}
  bool operator==(const struct s_nssai& s) const {
    if ((s.sst == this->sst) && (s.sd == this->sd)) {
      return true;
    } else {
      return false;
    }
  }

  s_nssai& operator=(const struct s_nssai& s) {
    sst = s.sst;
    sd  = s.sd;
    return *this;
  }

  std::string toString() const {
    std::string s = {};
    s.append("SST=").append(std::to_string(sst));
    s.append(", SD=").append(std::to_string(sd));
    return s;
  }

  size_t operator()(const s_nssai&) const {
    size_t res = HASH_SEED;
    res        = res * HASH_FACTOR + std::hash<uint32_t>()(sd);
    res        = res * HASH_FACTOR + std::hash<uint32_t>()(sst);
    return res;
  }

} snssai_t;

typedef struct dnai_s {
} dnai_t;

typedef struct dnn_upf_info_item_s {
  std::string dnn;
  std::unordered_set<std::string> dnai_list;
  // supported from R16.8
  std::map<std::string, std::string> dnai_nw_instance_list;
  // std::vector<std::string> pdu_session_types

  dnn_upf_info_item_s& operator=(const dnn_upf_info_item_s& d) {
    dnn                   = d.dnn;
    dnai_list             = d.dnai_list;
    dnai_nw_instance_list = d.dnai_nw_instance_list;
    return *this;
  }

  bool operator==(const dnn_upf_info_item_s& s) const { return dnn == s.dnn; }

  size_t operator()(const dnn_upf_info_item_s&) const {
    return std::hash<std::string>()(dnn);
  }

  std::string to_string() const {
    std::string s = {};

    s.append("DNN = ").append(dnn).append(", ");

    if (dnai_list.size() > 0) {
      s.append("DNAI list: {");

      for (const auto& dnai : dnai_list) {
        s.append("DNAI = ").append(dnai).append(", ");
      }
      s.append("}, ");
    }

    if (dnai_nw_instance_list.size() > 0) {
      s.append("DNAI NW Instance list: {");

      for (const auto& dnai_nw : dnai_nw_instance_list) {
        s.append("(")
            .append(dnai_nw.first)
            .append(", ")
            .append(dnai_nw.second)
            .append("),");
      }
      s.append("}, ");
    }
    return s;
  }

} dnn_upf_info_item_t;

typedef struct snssai_upf_info_item_s {
  mutable snssai_t snssai;
  mutable std::unordered_set<dnn_upf_info_item_t, dnn_upf_info_item_t>
      dnn_upf_info_list;

  snssai_upf_info_item_s& operator=(const snssai_upf_info_item_s& s) {
    snssai            = s.snssai;
    dnn_upf_info_list = s.dnn_upf_info_list;
    return *this;
  }

  bool operator==(const snssai_upf_info_item_s& s) const {
    return (snssai == s.snssai) and (dnn_upf_info_list == s.dnn_upf_info_list);
  }

  size_t operator()(const snssai_upf_info_item_s&) const {
    return snssai.operator()(snssai);
  }

  std::string to_string() const {
    std::string s = {};

    s.append("{" + snssai.toString() + ", ");

    if (dnn_upf_info_list.size() > 0) {
      s.append("{");

      for (auto dnn_upf : dnn_upf_info_list) {
        s.append(dnn_upf.to_string());
      }
      s.append("}, ");
    }
    return s;
  }

} snssai_upf_info_item_t;

typedef struct interface_upf_info_item_s {
  std::string interface_type;
  std::vector<struct in_addr> ipv4_addresses;
  std::vector<struct in6_addr> ipv6_addresses;
  std::string endpoint_fqdn;
  std::string network_instance;

  interface_upf_info_item_s& operator=(const interface_upf_info_item_s& i) {
    interface_type   = i.interface_type;
    ipv4_addresses   = i.ipv4_addresses;
    ipv6_addresses   = i.ipv6_addresses;
    endpoint_fqdn    = i.endpoint_fqdn;
    network_instance = i.network_instance;

    return *this;
  }

} interface_upf_info_item_t;

typedef struct upf_info_s {
  std::vector<interface_upf_info_item_t> interface_upf_info_list;
  std::vector<snssai_upf_info_item_t> snssai_upf_info_list;

  upf_info_s& operator=(const upf_info_s& s) {
    interface_upf_info_list = s.interface_upf_info_list;
    snssai_upf_info_list    = s.snssai_upf_info_list;
    return *this;
  }

  std::string to_string() const {
    std::string s = {};
    // TODO: Interface UPF Info List
    if (!snssai_upf_info_list.empty()) {
      s.append("S-NSSAI UPF Info: ");
      for (auto sn : snssai_upf_info_list) {
        s.append("{" + sn.snssai.toString() + ", ");
        for (auto d : sn.dnn_upf_info_list) {
          s.append("{DNN = " + d.dnn + "} ");
        }
        s.append("};");
      }
    }
    return s;
  }
} upf_info_t;

typedef struct patch_item_s {
  std::string op;
  std::string path;
  // std::string from;
  std::string value;

  nlohmann::json to_json() const {
    nlohmann::json json_data = {};
    json_data["op"]          = op;
    json_data["path"]        = path;
    json_data["value"]       = value;
    return json_data;
  }
} patch_item_t;

#define NRF_CURL_TIMEOUT_MS 100L
#define NNRF_NFM_BASE "/nnrf-nfm/"
#define NNRF_NF_REGISTER_URL "/nf-instances/"

#endif
