/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include "logger.hpp"
#include "upf_profile.hpp"
#include "string.hpp"
#include "3gpp_conversions.hpp"

using namespace oai::upf::app;
using namespace oai::common::sbi;

//------------------------------------------------------------------------------
upf_nf_profile::upf_nf_profile() : oai::sba::nf_profile(), upf_info() {
  nf_type = "NF_TYPE_UNKNOWN";
}

//------------------------------------------------------------------------------
upf_nf_profile::upf_nf_profile(const std::string& id)
    : oai::sba::nf_profile(id), upf_info() {
  nf_type = "NF_TYPE_UNKNOWN";
}

//------------------------------------------------------------------------------
upf_nf_profile::upf_nf_profile(const upf_nf_profile& other)
    : oai::sba::nf_profile(), upf_info() {
  *this = other;
}

//------------------------------------------------------------------------------
upf_nf_profile& upf_nf_profile::operator=(const upf_nf_profile& other) {
  if (this == &other) return *this;
  nf_instance_id   = other.nf_instance_id;
  nf_instance_name = other.nf_instance_name;
  nf_type          = other.nf_type;
  nf_status        = other.nf_status;
  heartBeat_timer  = other.heartBeat_timer;
  plmn_list        = other.plmn_list;
  snssais          = other.snssais;
  fqdn             = other.fqdn;
  ipv4_addresses   = other.ipv4_addresses;
  ipv6_addresses   = other.ipv6_addresses;
  priority         = other.priority;
  capacity         = other.capacity;
  json_data        = other.json_data;
  nf_services      = other.nf_services;
  custom_info      = other.custom_info;
  is_updated       = other.is_updated;
  upf_info         = other.upf_info;
  return *this;
}

//------------------------------------------------------------------------------
void upf_nf_profile::set_upf_info(const upf_info_t& s) {
  upf_info = s;
}

//------------------------------------------------------------------------------
void upf_nf_profile::add_upf_info_item(const snssai_upf_info_item_t& s) {
  upf_info.snssai_upf_info_list.push_back(s);
}

//------------------------------------------------------------------------------
void upf_nf_profile::get_upf_info(upf_info_t& s) const {
  s = upf_info;
}

//------------------------------------------------------------------------------
void upf_nf_profile::display() {
  oai::sba::nf_profile::display();
  Logger::upf_app().debug("    UPF Info:");
  for (const auto& s : upf_info.snssai_upf_info_list) {
    Logger::upf_app().debug(
        "        SNSSAI (SST %d, SD %s)", s.snssai.sst, s.snssai.sd.c_str());
    for (const auto& d : s.dnn_upf_info_list) {
      Logger::upf_app().debug("            DNN %s", d.dnn.c_str());
    }
  }
}

//------------------------------------------------------------------------------
void upf_nf_profile::to_json(nlohmann::json& data) const {
  oai::sba::nf_profile::to_json(data);
  data.erase("json_data");
  if (snssais.empty()) data["sNssais"] = nlohmann::json::array();
  data["fqdn"] = fqdn;

  // UPF info
  data["upfInfo"]                      = {};
  data["upfInfo"]["sNssaiUpfInfoList"] = nlohmann::json::array();
  for (auto s : upf_info.snssai_upf_info_list) {
    nlohmann::json tmp    = {};
    tmp["sNssai"]["sst"]  = s.snssai.sst;
    tmp["sNssai"]["sd"]   = s.snssai.sd;
    tmp["dnnUpfInfoList"] = nlohmann::json::array();
    for (auto d : s.dnn_upf_info_list) {
      nlohmann::json dnn_json = {};
      dnn_json["dnn"]         = d.dnn;
      tmp["dnnUpfInfoList"].push_back(dnn_json);
    }
    data["upfInfo"]["sNssaiUpfInfoList"].push_back(tmp);
  }

  Logger::upf_app().debug("UPF profile to JSON:\n %s", data.dump().c_str());
}

//------------------------------------------------------------------------------
void upf_nf_profile::from_json(const nlohmann::json& data) {
  if (data.find("nfInstanceId") != data.end()) {
    nf_instance_id = data["nfInstanceId"].get<std::string>();
  }

  if (data.find("nfInstanceName") != data.end()) {
    nf_instance_name = data["nfInstanceName"].get<std::string>();
  }

  if (data.find("nfType") != data.end()) {
    nf_type = data["nfType"].get<std::string>();
  }

  if (data.find("nfStatus") != data.end()) {
    nf_status = data["nfStatus"].get<std::string>();
  }

  if (data.find("heartBeatTimer") != data.end()) {
    heartBeat_timer = data["heartBeatTimer"].get<int>();
  }
  // sNssais
  if (data.find("sNssais") != data.end()) {
    for (auto it : data["sNssais"]) {
      snssai_t s = {};
      if (it["sNssai"].find("sst") != it["sNssai"].end()) {
        s.sst = it["sNssai"]["sst"].get<int>();
        if (it["sNssai"].find("sd") != it["sNssai"].end()) {
          s.sd = it["sNssai"]["sd"].get<std::string>();
        }
        snssais.push_back(s);
      }
    }
  }

  if (data.find("ipv4Addresses") != data.end()) {
    nlohmann::json addresses = data["ipv4Addresses"];

    for (auto it : addresses) {
      struct in_addr addr4 = {};
      std::string address  = it.get<std::string>();
      unsigned char buf_in_addr[sizeof(struct in_addr)];
      if (inet_pton(AF_INET, oai::utils::trim(address).c_str(), buf_in_addr) ==
          1) {
        memcpy(&addr4, buf_in_addr, sizeof(struct in_addr));
      } else {
        Logger::upf_app().warn(
            "Address conversion: Bad value %s",
            oai::utils::trim(address).c_str());
      }
      add_nf_ipv4_addresses(addr4);
    }
  }

  if (data.find("priority") != data.end()) {
    priority = data["priority"].get<int>();
  }

  if (data.find("capacity") != data.end()) {
    capacity = data["capacity"].get<int>();
  }

  // UPF info
  upf_info.snssai_upf_info_list.clear();
  if (data.find("upfInfo") != data.end()) {
    nlohmann::json info = data["upfInfo"];

    if (info.find("sNssaiUpfInfoList") != info.end()) {
      nlohmann::json snssai_upf_info_list = info["sNssaiUpfInfoList"];

      for (auto it : snssai_upf_info_list) {
        snssai_upf_info_item_t upf_info_item = {};
        bool found_snssai                    = false;
        if (it.find("sNssai") != it.end()) {
          if (it["sNssai"].find("sst") != it["sNssai"].end()) {
            upf_info_item.snssai.sst = it["sNssai"]["sst"].get<int>();
            found_snssai             = true;
            if (it["sNssai"].find("sd") != it["sNssai"].end()) {
              upf_info_item.snssai.sd = it["sNssai"]["sd"].get<std::string>();
            }
          }
        }
        if (it.find("dnnUpfInfoList") != it.end()) {
          for (auto d : it["dnnUpfInfoList"]) {
            if (d.find("dnn") != d.end()) {
              dnn_upf_info_item_t dnn_item = {};
              dnn_item.dnn                 = d["dnn"].get<std::string>();
              upf_info_item.dnn_upf_info_list.insert(dnn_item);
            }
          }
        }
        if (found_snssai)
          upf_info.snssai_upf_info_list.push_back(upf_info_item);
      }
    }
  }

  display();
}

//------------------------------------------------------------------------------
void upf_nf_profile::handle_heartbeart_timeout(uint64_t ms) {
  Logger::upf_app().info(
      "Handle heartbeart timeout profile %s, time %d", nf_instance_id.c_str(),
      ms);
  set_nf_status("SUSPENDED");
}
