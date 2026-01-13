/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file SessionPrograms.h
 * @brief Session Programs Container
 *
 * Container for BPF programs associated with a PFCP session.
 * Manages QER and FAR programs for the data path.
 */

#ifndef SESSION_PROGRAMS_H_
#define SESSION_PROGRAMS_H_

#include <memory>
//#include <upf_xdp_user.h>
#include <unistd.h>

// Forward declarations
class UPF_XDPProgram;
class QERProgram;

/**
 * @class SessionPrograms
 * @brief Container for session-specific BPF programs
 *
 * Holds references to BPF programs that implement the data path
 * for a PFCP session. Each session may have:
 * - QER program for QoS enforcement
 * - FAR program for forwarding actions (mandatory)
 *
 * @note Follows Google C++ Style Guide
 */
class SessionPrograms {
 public:
  /**
   * @brief Constructor
   * @param upf_xdp_program Shared pointer to UPF XDP program
   */
  explicit SessionPrograms(std::shared_ptr<UPF_XDPProgram> upf_xdp_program);

  /**
   * @brief Destructor - tears down associated BPF programs
   */
  virtual ~SessionPrograms();

  /**
   * @brief Get PFCP program reference
   * @return Shared pointer to UPF XDP program
   */
  std::shared_ptr<UPF_XDPProgram> GetPFCPProgram() const;

  /**
   * @brief Set QER program reference
   * @param Shared pointer to QER program
   */
  void SetQERProgram(std::shared_ptr<QERProgram> qer_program);

  /**
   * @brief Get QER program reference
   * @return Shared pointer to QER program
   */
  std::shared_ptr<QERProgram> GetQERProgram() const;

 private:
  /// UPF XDP program reference
  std::shared_ptr<UPF_XDPProgram> upf_xdp_program_;

  /// QER program reference
  std::shared_ptr<QERProgram> qer_program_;
};

#endif  // SESSION_PROGRAMS_H_
