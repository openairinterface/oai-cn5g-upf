/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file qer_tc_user.h
 * @brief TC-BPF program for QoS Enforcement Rules (QER)
 *
 * This class manages Traffic Control (TC) BPF programs for QoS enforcement
 * in the User Plane Function. It implements QoS Enforcement Rules (QER) as
 * defined in 3GPP TS 29.244.
 *
 * QoS Enforcement Overview:
 * - Uses Linux TC (Traffic Control) with HTB (Hierarchical Token Bucket) qdisc
 * - Enforces MBR (Maximum Bit Rate) and GBR (Guaranteed Bit Rate)
 * - Implements per-QFI (QoS Flow Identifier) traffic shaping
 * - Supports 5G QoS model with default and dedicated flows
 *
 * Architecture:
 * 1. Root HTB qdisc: Overall rate limiting
 * 2. PDU Session class: Per-session bandwidth allocation
 * 3. QoS Flow classes: Per-QFI traffic shaping
 * 4. TC-BPF filter: Packet classification to classes
 *
 * TC Hierarchy:
 * ```
 * Root qdisc (1:0)
 * ├─ PDU Session class (1:SEID)
 * │  ├─ Default QoS Flow (1:default_id)
 * │  ├─ QoS Flow 1 (1:qfi_1) - GBR/MBR
 * │  └─ QoS Flow 2 (1:qfi_2) - GBR/MBR
 * └─ ...
 * ```
 *
 * QER Parameters (3GPP TS 29.244):
 * - QER ID: Unique identifier
 * - QFI: QoS Flow Identifier (3GPP TS 38.415)
 * - MBR: Maximum Bit Rate (uplink/downlink)
 * - GBR: Guaranteed Bit Rate (uplink/downlink)
 * - Gate Status: OPEN/CLOSED per direction
 *
 * TC Commands Generated:
 * ```bash
 * # Root qdisc
 * tc qdisc add dev <if> root handle 1:0 htb default <id> r2q <value>
 *
 * # PDU session class
 * tc class add dev <if> parent 1: classid 1:<seid> htb rate <rate>kbit
 *
 * # QoS flow class
 * tc class add dev <if> parent 1:<seid> classid 1:<minor> \
 *    htb rate <gbr>kbit ceil <mbr>kbit
 *
 * # BPF classifier
 * tc filter add dev <if> parent 1:0 protocol ip bpf \
 *    obj qer_tc_kern.c.o classid 1: direct-action
 * ```
 *
 * Reference Standards:
 * - 3GPP TS 29.244: PFCP QER definition
 * - 3GPP TS 38.415: 5G QoS model and QFI
 * - 3GPP TS 23.501: 5G System Architecture
 * - Linux TC documentation: man tc-htb(8), man tc-bpf(8)
 *
 * @note This implementation follows Google C++ Style Guide
 */

#ifndef QER_TC_USER_H_
#define QER_TC_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <unordered_map>
#include <vector>
#include <qer_tc_kern_skel.h>
#include <wrappers/BPFMap.hpp>
#include <BPFProgram.h>
#include <pfcp_session.hpp>
#include "upf_config.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

// Forward declarations
class BPFMaps;
class BPFMap;

/**
 * @brief Type alias for QER TC-BPF program lifecycle
 */
using QERProgramLifeCycle = ProgramLifeCycle<qer_tc_kern_c>;

/**
 * @class QERProgram
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
class QERProgram : public BPFProgram {
 public:
  /**
   * @brief Constructor - initializes QER TC-BPF program
   *
   * @param upf_cfg UPF configuration with interface settings
   *
   * @throws std::runtime_error if skeleton creation fails
   * @throws std::runtime_error if map configuration fails
   */
  explicit QERProgram(const upf_config& upf_cfg);

  /**
   * @brief Destructor - cleans up TC-BPF program
   */
  virtual ~QERProgram();

  /**
   * @brief Setup TC-BPF program for a PDU session
   *
   * Creates the complete TC hierarchy for QoS enforcement:
   * 1. Root HTB qdisc (if not exists)
   * 2. PDU session class
   * 3. QoS flow classes for each QER
   * 4. TC-BPF filter for classification
   *
   * @param seid Session Endpoint Identifier (used as class ID)
   * @param qers Vector of QERs for this session
   * @param pdrs Vector of PDRs (for QER-PDR mapping)
   *
   * @throws std::runtime_error if TC command fails
   * @throws std::runtime_error if interface not found
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
   * @brief Teardown TC-BPF program
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
  void ConfigureQerMaps(struct qer_tc_kern_c* skel, const upf_config& upf_cfg);

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

  // Default class configuration (HTB parameters)
  uint32_t default_class_handle_;  ///< TC class handle for default flow
  uint32_t default_class_rate_;    ///< Default rate in kbps
  uint32_t default_class_ceil_;    ///< Default ceil in kbps
  uint32_t r2q_root_;              ///< Root qdisc r2q parameter

  uint64_t seid_ =
      0;  ///< SEID this QoS class tree belongs to (scoped teardown)

  /// HTB class minor-ids created by Setup(), in creation order (parent before
  /// children). TearDown() deletes them in reverse so children are removed
  /// before their parent (HTB refuses to delete a class that still has
  /// children). Scoped per-session so the shared root qdisc and other
  /// sessions' classes are left untouched.
  std::vector<uint16_t> created_class_ids_;

  // PDR lookup map
  std::unordered_map<uint32_t, std::shared_ptr<pfcp::pfcp_pdr>> pdr_map_;

  // BPF program components
  std::shared_ptr<BPFMaps> maps_;                   ///< All BPF maps
  qer_tc_kern_c* skeleton_;                         ///< BPF skeleton
  std::shared_ptr<BPFMap> egress_ifindex_map_;      ///< Egress interfaces
  std::shared_ptr<QERProgramLifeCycle> lifecycle_;  ///< Lifecycle manager
  std::shared_ptr<BPFMap> qos_flow_params_map_;     ///< QoS flow parameters
};

#endif  // QER_TC_USER_H_
