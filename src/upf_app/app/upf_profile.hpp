/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UPF_PROFILE_HPP_SEEN
#define FILE_UPF_PROFILE_HPP_SEEN

#include <nlohmann/json.hpp>

#include "nf_profile.hpp"

namespace oai::upf::app {

class upf_nf_profile : public oai::sba::nf_profile {
 public:
  upf_nf_profile();
  explicit upf_nf_profile(const std::string& id);
  upf_nf_profile(const upf_nf_profile& other);
  upf_nf_profile& operator=(const upf_nf_profile& other);
  ~upf_nf_profile() override = default;

  void set_upf_info(const oai::common::sbi::upf_info_t& info);
  void add_upf_info_item(const oai::common::sbi::snssai_upf_info_item_t& info);
  void get_upf_info(oai::common::sbi::upf_info_t& info) const;

  void display() override;
  void to_json(nlohmann::json& data) const override;
  void from_json(const nlohmann::json& data);

  void handle_heartbeart_timeout(uint64_t ms);

 private:
  oai::common::sbi::upf_info_t upf_info;
};

}  // namespace oai::upf::app

#endif
