/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UPF_SBI_HPP_SEEN
#define FILE_UPF_SBI_HPP_SEEN

#include "itti.hpp"
#include "nf_service.hpp"
#include "upf_profile.hpp"

namespace oai::upf::app {

#define TASK_UPF_SBI_TIMEOUT_NRF_HEARTBEAT (1)
#define TASK_UPF_SBI_TIMEOUT_NRF_DEREGISTRATION (2)
#define TASK_UPF_SBI_TIMEOUT_NRF_REGISTRATION (3)

class upf_sbi : public oai::sba::nf_service {
 public:
  upf_sbi();
  upf_sbi(upf_sbi const&)        = delete;
  ~upf_sbi() override            = default;
  void operator=(upf_sbi const&) = delete;

  bool send_update_nf_instance(
      const std::string& url, const nlohmann::json& data);

  bool register_to_nrf();
  bool deregister_to_nrf();
  void generate_upf_profile();

  void timer_nrf_heartbeat_timeout(timer_id_t timer_id, uint64_t arg2_user);
  void timer_nrf_deregistration(timer_id_t timer_id, uint64_t arg2_user);
  void timer_nrf_registration(timer_id_t timer_id, uint64_t arg2_user);

 protected:
  bool nrf_registration_enabled() const override;
  uint64_t nrf_registration_retry_seconds() const override;
  bool registration_succeeded(
      const oai::sba::sbi_http_response& response) const override;
  void on_registration_outcome(
      bool success, const oai::sba::sbi_http_response& response) override;

 private:
  void get_nrf_api_root(std::string& api_root) const;

  upf_nf_profile upf_profile;
  timer_id_t timer_nrf_heartbeat = {};
  int32_t nrf_retry_interval     = 5;
  timer_id_t timer_nrf_retry     = {};
};

}  // namespace oai::upf::app

#endif /* FILE_UPF_SBI_HPP_SEEN */
