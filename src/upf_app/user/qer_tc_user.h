/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef QER_TC_USER_H_
#define QER_TC_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <qer_tc_kern_skel.h>
#include <wrappers/BPFMap.hpp>
#include <BPFProgram.h>
#include <pfcp_session.hpp>
#include "startup_banner.hpp"    // QosFlowInfo
#include "upf_network_config.h"  // upf::g_net_cfg — no upf_config.hpp

// Forward declarations
class BPFMaps;
class BPFMap;

/* ==========================================================================
 * Type alias
 * ========================================================================== */
/**
 * @brief Type alias for QER TC-BPF program lifecycle
 */
using QerTCProgramLifeCycle = ProgramLifeCycle<qer_tc_kern_c>;

/* ==========================================================================
 * QERTCProgram
 * ========================================================================== */
/**
 * @class QERTCProgram
 * @brief Manages TC-BPF programs for QoS Enforcement Rules
 *
 * This class implements 5G QoS enforcement using Linux Traffic Control (TC)
 * with BPF classifiers. It translates PFCP QER Information Elements into
 * TC HTB classes and enforces rate limits using kernel traffic shaping.
 *
 * Key Responsibilities:
 * - Create HTB qdisc hierarchy for QoS enforcement
 * - Map QERs to TC classes based on QFI
 * - Configure GBR (Guaranteed Bit Rate) and MBR (Maximum Bit Rate)
 * - Attach TC-BPF filter for packet classification
 * - Manage default and dedicated QoS flows
 * - Handle PDU session bandwidth allocation
 *
 * QoS Flow Types (3GPP TS 23.501):
 * - Default QoS Flow: Always present, non-GBR
 * - Dedicated QoS Flows: Optional, can be GBR or non-GBR
 *
 * Rate Parameters:
 * - GBR: Guaranteed bandwidth (rate in HTB)
 * - MBR: Maximum bandwidth (ceil in HTB)
 * - Default values: rate=1024 kbps, ceil=2048 kbps
 *
 * Thread Safety: Not thread-safe. Use from single thread.
 *
 * @note This implementation follows Google C++ Style Guide
 * @note Inherits from BPFProgram base class
 */
class QERTCProgram : public BPFProgram {
 public:
  /**
   * @brief Constructor - initializes QER TC-BPF program
   *
   * @param upf_cfg UPF configuration with interface settings
   *
   * @throws std::runtime_error if skeleton creation fails
   * @throws std::runtime_error if map configuration fails
   */
  /**
   * @brief Constructor
   *
   * Network configuration (interface names, map sizing limits) is read
   * from upf::g_net_cfg which must be populated by
   * control/Configuration.cpp before the first QERTCProgram is created.
   *
   * @throws std::runtime_error if skeleton creation fails
   */
  explicit QERTCProgram();

  /**
   * @brief Destructor - cleans up TC-BPF program
   */
  virtual ~QERTCProgram();

  /**
   * @brief Setup or update the TC-BPF QoS enforcement of a PDU session
   *
   * Brings the TC hierarchy in line with @p qers:
   * 1. Root HTB qdisc (if not exists)
   * 2. PDU session class
   * 3. QoS flow classes for each QER
   * 4. TC-BPF filter for classification
   *
   * Call it again for the same session whenever its QERs change. Classes
   * that are still wanted are changed in place (`tc class replace`, which
   * also re-creates one deleted from outside the UPF), so a new rate
   * applies without the flow losing its class; new ones are added and ones
   * no longer wanted are deleted, children first.
   *
   * @param seid Session Endpoint Identifier (used as class ID)
   * @param qers Vector of QERs for this session
   * @param pdrs Vector of PDRs (for QER-PDR mapping)
   *
   * @throws RuleApplyError if any part of the enforcement could not be
   *         applied, naming the QER it failed for. The rest is still
   *         applied, and the next call retries what failed.
   *
   * Usage:
   * @code
   * qer_program->Setup(seid, session->qers, session->pdrs);
   * @endcode
   */
  void Setup(
      uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> qers,
      std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs);

  /**
   * @brief Get all BPF maps
   *
   * @return std::shared_ptr<BPFMaps> Container of all maps
   */
  std::shared_ptr<BPFMaps> GetMaps();

  /**
   * @brief Release this session's shaping state and the BPF program
   *
   * Deletes the tc classes Setup() created, children first, then destroys
   * the skeleton. The shared root qdisc, the shared BPF filter and the N6
   * tc_redirect hook are left in place, since other sessions use them.
   * Safe to call more than once.
   */
  void TearDown();

  /**
   * @brief Get egress interface index map
   *
   * Maps flow direction (UPLINK/DOWNLINK) to interface index.
   *
   * @return std::shared_ptr<BPFMap> Egress interface map
   */
  std::shared_ptr<BPFMap> GetEgressIfindexMap() const;

  /**
   * @brief Get 5G QoS flow parameters map
   *
   * Stores QoS parameters (MBR, GBR, QFI) per flow.
   *
   * @return std::shared_ptr<BPFMap> QoS flow params map
   */
  std::shared_ptr<BPFMap> Get5GQoSFlowParamsMap() const;

  // TC qdisc/class query methods
  bool NoHtbRootQdisc(const std::string& interface);
  bool NoHtbDefaultClass(const std::string& interface);
  bool NoTcFilterBpf(const std::string& interface);

  /**
   * @brief Find default QER with default QFI
   *
   * The default QER has neither GBR nor MBR set.
   *
   * @param qers Vector of QERs to search
   * @return std::shared_ptr<pfcp::pfcp_qer> Default QER, or nullptr
   */
  std::shared_ptr<pfcp::pfcp_qer> RetrieveDefaultQerWithDefaultQfi(
      std::vector<std::shared_ptr<pfcp::pfcp_qer>> qers);

  // Default class configuration
  void SetDefaultClassHandle(uint32_t handle) {
    default_class_handle_ = handle;
  }
  uint32_t GetDefaultClassHandle() const { return default_class_handle_; }

  void SetDefaultClassRate(uint32_t rate) { default_class_rate_ = rate; }
  uint32_t GetDefaultClassRate() const { return default_class_rate_; }

  void SetDefaultClassCeil(uint32_t ceil) { default_class_ceil_ = ceil; }
  uint32_t GetDefaultClassCeil() const { return default_class_ceil_; }

  void SetR2qRoot(uint32_t r2q) { r2q_root_ = r2q; }
  uint32_t GetR2qRoot() const { return r2q_root_; }

 private:
  // ==========================================================================
  // Private helpers
  // ==========================================================================
  /**
   * @brief Initialize BPF map wrappers
   */
  void InitializeMaps();

  /**
   * @brief Configure QER-specific BPF maps
   *
   * @param skel Opened BPF skeleton
   * @param upf_cfg Configuration
   */
  void ConfigureQerMaps(struct qer_tc_kern_c* skel);

  /**
   * @brief Build QER ID to PDR mapping
   *
   * Creates internal map for quick PDR lookup by QER ID.
   *
   * @param pdrs Vector of PDRs
   */
  void BuildPdrMap(const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs);

  /**
   * @brief Get PDR associated with a QER ID
   *
   * @param qer_id QER identifier
   * @return std::shared_ptr<pfcp::pfcp_pdr> PDR or nullptr
   */
  std::shared_ptr<pfcp::pfcp_pdr> GetPdrByQerId(uint32_t qer_id) const;

  /**
   * @brief One HTB class of this session, as Setup() wants it or created it
   */
  struct TcClass {
    uint16_t minor;      ///< classid 1:minor
    uint16_t parent;     ///< parent classid 1:parent, 0 for the root qdisc
    uint64_t rate_kbps;  ///< HTB rate
    uint64_t ceil_kbps;  ///< HTB ceil, 0 to leave it to HTB (= rate)
    uint32_t quantum;    ///< HTB quantum, 0 to leave it to r2q
    uint32_t qer_id;     ///< QER it enforces, 0 for the PDU session class
    std::string role;    ///< What it is, for the logs
  };

  /**
   * @brief The classes a session with these QERs needs, parents first
   *
   * @param flows Filled with one row per QoS flow, for the flow table
   */
  std::vector<TcClass> BuildTcClasses(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_qer>>& qers,
      uint32_t session_rate_kbps, std::vector<QosFlowInfo>& flows);

  /**
   * @brief Change, add and delete classes until they match @p wanted
   *
   * @return IDs of the QERs whose class could not be brought in line,
   *         0 standing for the PDU session class
   */
  std::set<uint32_t> ApplyTcClasses(const std::vector<TcClass>& wanted);

  /**
   * @brief Run `tc class add`, or `tc class replace` if @p update
   */
  bool WriteTcClass(const TcClass& tc_class, bool update);

  /**
   * @brief Run `tc class del` for one class
   */
  bool DeleteTcClass(const TcClass& tc_class);

  /**
   * @brief Delete the tc classes recorded by Setup(), children first
   *
   * Only classes whose `tc class add` succeeded are recorded, so a class id
   * that already existed (for example, held by another session) is never
   * deleted here.
   */
  void DeleteTcClasses();

  // Default class configuration (HTB parameters)
  uint32_t default_class_handle_;  ///< TC class handle for default flow
  uint32_t default_class_rate_;    ///< Default rate in kbps
  uint32_t default_class_ceil_;    ///< Default ceil in kbps
  uint32_t r2q_root_;              ///< Root qdisc r2q parameter

  // ==========================================================================
  // Skeleton and lifecycle
  // ==========================================================================
  qer_tc_kern_c* skeleton_;                           ///< BPF skeleton
  std::shared_ptr<QerTCProgramLifeCycle> lifecycle_;  ///< Lifecycle manager

  // ==========================================================================
  // Maps
  // ==========================================================================
  std::shared_ptr<BPFMaps> maps_;  ///< All BPF maps
  std::unordered_map<uint32_t, std::shared_ptr<pfcp::pfcp_pdr>>
      pdr_map_;                                  /// PDR lookup map
  std::shared_ptr<BPFMap> egress_ifindex_map_;   ///< Egress interfaces
  std::shared_ptr<BPFMap> qos_flow_params_map_;  ///< QoS flow parameters

  // ==========================================================================
  // tc classes created by Setup(), released by TearDown()
  // ==========================================================================
  std::string tc_iface_;          ///< Interface the classes live on
  std::vector<TcClass> classes_;  ///< In creation order, parents first
};

#endif  // QER_TC_USER_H_
