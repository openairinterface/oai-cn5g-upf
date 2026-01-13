#ifndef __SESSION_OBSERVER_H__
#define __SESSION_OBSERVER_H__

#include <stdlib.h>

/**
 * @class ISessionObserver
 * @brief Observer interface for session program lifecycle events
 *
 * Allows components to be notified of session program state changes.
 * This decouples SessionProgramManager from UserPlaneComponent.
 *
 * Pattern: Observer Design Pattern
 * Purpose: Notify observers when session programs are created/updated/destroyed
 */
class ISessionObserver {
 public:
  virtual ~ISessionObserver() = default;

  /**
   * @brief Called when new session program is created
   * @param program_id Program identifier
   * @param file_descriptor BPF program file descriptor
   */
  virtual void OnNewSessionProgram(
      uint32_t program_id, uint32_t file_descriptor) = 0;

  /**
   * @brief Called when session program is destroyed
   * @param program_id Program identifier
   */
  virtual void OnDestroySessionProgram(uint32_t program_id) = 0;

  /**
   * @brief Called when session program is updated
   * @param program_id Program identifier
   * @param file_descriptor New BPF program file descriptor
   */
  virtual void OnUpdateSessionProgram(
      uint32_t program_id, uint32_t file_descriptor) = 0;
};

#endif  // __SESSION_OBSERVER_H__
