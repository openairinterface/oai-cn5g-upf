/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#ifndef __QER_TC_USER_H__
#define __QER_TC_USER_H__

#include <ProgramLifeCycle.hpp>
#include <atomic>
#include <linux/bpf.h>  // manage maps (e.g. bpf_update*)
#include <memory>
#include <mutex>
#include <signal.h>  // signals
#include <qer_tc_kernel_skel.h>
#include <wrappers/BPFMap.hpp>
#include <BPFProgram.h>
#include "interfaces.h"

// #include <netlink/netlink.h>
// #include <netlink/route/qdisc.h>
#include <qos_flow.h>
#include <pfcp_session.hpp>

#include "upf_config.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

class BPFMaps;
class BPFMap;
class SessionManager;
// class RulesUtilities;

using QERProgramLifeCycle = ProgramLifeCycle<qer_tc_kernel_c>;

class QERProgram : public BPFProgram {
 public:
  explicit QERProgram(const upf_config& upf_cfg);
  virtual ~QERProgram();
  void setup();
  void setup(
      uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer,
      std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs);
  std::shared_ptr<BPFMaps> getMaps();
  void tearDown();
  std::shared_ptr<BPFMap> getEgressIfindexMap() const;
  std::shared_ptr<BPFMap> geGtpUTunnelMap() const;
  std::shared_ptr<BPFMap> getSdfFilterMap() const;
  std::shared_ptr<BPFMap> get5GQoSFlowParamsMap() const;
  bool no_htb_root_qdisc(const std::string interface);
  bool no_htb_default_class(const std::string interface);
  bool no_tc_filter_bpf(const std::string interface);
  std::shared_ptr<pfcp::pfcp_qer> retrive_default_qer_with_default_qfi(
      std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer);

  void setDefaultClassHandle(uint32_t handle) {
    m_default_class_handle = handle;
  }
  uint32_t getDefaultClassHandle() const { return m_default_class_handle; }

  void setDefaultClassRate(uint32_t rate) { m_default_class_rate = rate; }
  uint32_t getDefaultClassRate() const { return m_default_class_rate; }

  void setDefaultClassCeil(uint32_t ceil) { m_default_class_ceil = ceil; }
  uint32_t getDefaultClassCeil() const { return m_default_class_ceil; }

  void setR2qRoot(uint32_t r2q) { m_r2q_root = r2q; }
  uint32_t getR2qRoot() const { return m_r2q_root; }
  /*---------------------------------------------------------------------------------------------------------------*/
 private:
  uint32_t m_default_class_handle;
  uint32_t m_default_class_rate;  // kbps
  uint32_t m_default_class_ceil;  // kbps
  uint32_t m_r2q_root;            // qdisc r2q

  void initializeMaps();
  void configureQerMaps(
      struct qer_tc_kernel_c* skel, const upf_config& upf_cfg);

  void build_pdr_map(const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs);
  std::shared_ptr<pfcp::pfcp_pdr> get_pdr_by_qer_id(uint32_t qer_id) const;

  std::unordered_map<uint32_t, std::shared_ptr<pfcp::pfcp_pdr>> pdr_map;
  std::shared_ptr<BPFMaps> mpMaps;
  qer_tc_kernel_c* spSkeleton;
  std::shared_ptr<BPFMap> mpEgressIfindexMap;
  std::shared_ptr<QERProgramLifeCycle> mpLifeCycle;
  std::shared_ptr<BPFMap> mp5GQoSFlowParamsMap;
  std::vector<struct s_fiveQosFlow> qosFlowsQfis;
};

#endif  // __QER_TC_USER_H__
