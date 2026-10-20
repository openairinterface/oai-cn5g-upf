/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef RULE_APPLY_ERROR_H_
#define RULE_APPLY_ERROR_H_

#include <cstdint>
#include <stdexcept>
#include <string>

/**
 * @brief A PFCP rule that was stored but could not be applied to the datapath
 *
 * Thrown by the datapath programs so that the PFCP Session Modification
 * Response carries cause "Rule creation/modification Failure" and a Failed
 * Rule ID naming the rule, rather than "Request accepted".
 *
 * @see 3GPP TS 29.244 V17.10.0 §8.2.1  — Cause value 73
 * @see 3GPP TS 29.244 V17.10.0 §8.2.80 — Failed Rule ID
 */
class RuleApplyError : public std::runtime_error {
 public:
  /**
   * @param rule_type Failed Rule ID type (pfcp::FAILED_RULE_ID_TYPE_*)
   * @param rule_id   ID of the rule that failed to be applied
   * @param what      Description of the failure, for the logs
   */
  RuleApplyError(uint8_t rule_type, uint32_t rule_id, const std::string& what)
      : std::runtime_error(what), rule_type_(rule_type), rule_id_(rule_id) {}

  uint8_t rule_type() const { return rule_type_; }
  uint32_t rule_id() const { return rule_id_; }

 private:
  uint8_t rule_type_;
  uint32_t rule_id_;
};

#endif  // RULE_APPLY_ERROR_H_
