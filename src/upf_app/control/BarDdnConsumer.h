/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef BAR_DDN_CONSUMER_H_
#define BAR_DDN_CONSUMER_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <thread>

#include <bar_types.h>

#include "3gpp_29.244.h"
#include "msg_pfcp.hpp"

class BPFMap;
struct ring_buffer;

namespace oai {
namespace upf {
namespace app {

enum class DldrDispatch {
  kEnqueued,       ///< itti send_msg() == RETURNok; N4 task owns it now
  kNoAssociation,  ///< no usable PFCP association for this CP F-SEID
  kEnqueueFailed   ///< association fine, ITTI refused the message
};

/**
 * @class BarDdnConsumer
 * @brief Polls bar_ddn_ringbuf_map and turns each DDN (Downlink Data
 * Notification) event of the XDP BAR program into a PFCP Downlink Data Report.
 *
 * Owned by UserPlaneComponent. Start() is called from setup_bpf() once the
 * BAR program is loaded. Stop() runs early in UserPlaneComponent::TearDown(),
 * before the BAR maps, the N4 task and pfcp_switch go away. Both are
 * idempotent, because TearDown() can run twice.
 */
class BarDdnConsumer {
 public:
  /** @brief UP SEID -> CP F-SEID resolution.
   *
   * Defaults to pfcp_switch::get_cp_fseid_by_up_seid() on the live
   * pfcp_switch. It is a member rather than a direct call so that a test can
   * drive the resolved and stale-SEID branches without a pfcp_switch, which
   * owns tun interfaces and worker threads.
   */
  using CpFseidResolver = std::function<bool(uint64_t, pfcp::fseid_t&)>;

  /** @brief Hand-off of a DLDR (Downlink Data Report) to TASK_UPF_N4.
   *
   * Arguments: (cp_fseid, report, up_seid, pdr_id). Defaults to the static
   * upf_n4::enqueue_session_report_request(), which does not use upf_n4_inst
   * (~upf_app() deletes it without setting it to null). (up_seid, pdr_id)
   * goes with the report, so that TASK_UPF_N4 can release the latch if the
   * SMF never answers. A member so that a test can replace it.
   */
  using DldrDispatcher = std::function<DldrDispatch(
      const pfcp::fseid_t&, const pfcp::pfcp_session_report_request&, uint64_t,
      uint16_t)>;

  /** @brief Release the kernel one-shot DDN latch of a session.
   *
   * Defaults to SessionProgramManager::ResetBarState() ->
   * BARProgram::ResetBarState(), which writes with BPF_EXIST and so can only
   * overwrite an entry, never create one.
   *
   * @warning Only called for a session that resolved, i.e. is still present.
   *          A stale UP SEID must be dropped and counted -- see the re-arm
   *          contract on HandleEvent().
   */
  using BarStateRearm = std::function<bool(uint64_t)>;

  /** @brief Snapshot of the consumer counters */
  struct Counters {
    uint64_t received;    ///< Well-formed records taken off the ring
    uint64_t malformed;   ///< Records dropped on the size check
    uint64_t resolved;    ///< Records whose UP SEID mapped to a live session
    uint64_t stale_seid;  ///< Records dropped: UP SEID unknown / torn down
    uint64_t dispatched;  ///< DLDRs accepted by TASK_UPF_N4 (RETURNok)
    uint64_t no_association;  ///< Hand-off failed: no PFCP association
    uint64_t enqueue_failed;  ///< Hand-off failed: ITTI refused the message
    uint64_t rearmed;         ///< Latch releases attempted after a failure
  };

  /** @brief ring_buffer__poll() seam: (timeout_ms) -> libbpf return code.
   *
   * Defaults to ring_buffer__poll(ring_, timeout_ms), guarded against a null
   * ring_. It is a member so that a test can reach the poll loop's
   * fatal-error exit, which must clear running_: making the real
   * ring_buffer__poll() fail needs a loaded map and CAP_BPF.
   */
  using RingPoller = std::function<int(int)>;

  /** @brief Poll timeout handed to ring_buffer__poll(); bounds shutdown
   *         latency without turning the loop into a spin. */
  static constexpr int kPollTimeoutMs = 200;

  BarDdnConsumer();
  ~BarDdnConsumer();

  BarDdnConsumer(const BarDdnConsumer&)            = delete;
  BarDdnConsumer& operator=(const BarDdnConsumer&) = delete;

  /**
   * @brief Attach to the DDN ring and start the poll thread.
   *
   * On failure (no map, no fd, ring_buffer__new() fails) it logs and starts
   * nothing. It can be called again after the poll loop died on an error:
   * the old thread and ring are cleaned up first.
   *
   * @param ddn_ringbuf bar_ddn_ringbuf_map, from
   *        UPF_XDPProgram::GetBarProgram()->GetBarDdnRingbuf()
   *        (GetMapByName() does not know the ring).
   * @return true if the poll thread is running.
   */
  bool Start(const std::shared_ptr<BPFMap>& ddn_ringbuf);

  /** @brief Stop and join the poll thread, then free the ring. Idempotent.
   *
   * Safe to call from the poll thread itself: the thread is then detached
   * instead of joined. Joining itself throws std::system_error, and on the
   * path that does this (a SIGSEGV on the poll thread ->
   * SignalHandler::TearDown) that would be an uncaught exception inside a
   * signal handler, i.e. std::terminate.
   */
  void Stop();

  /** @brief True while the poll thread is alive.
   *
   * Set by Start(), cleared by Stop() and also by the poll loop itself when
   * ring_buffer__poll() fails fatally, so a dead consumer never reports
   * healthy.
   */
  bool IsRunning() const;

  /** @brief Current counter values. */
  Counters GetCounters() const;

  /**
   * @brief Handle one ring record.
   *
   * Public because it holds all the decision logic of this class and a test
   * can drive it directly; production reaches it through OnDdnEvent().
   *
   * @par Re-arm contract
   * The XDP program takes the latch when it produces the event, so a DDN that
   * is not turned into a report silences the session unless the latch is
   * released. There are four outcomes:
   *
   *   | outcome                     | report sent | ResetBarState |
   *   |-----------------------------|-------------|---------------|
   *   | enqueued (RETURNok)         | yes (N4)    | NO (see below)|
   *   | ITTI enqueue refused        | no          | YES           |
   *   | no PFCP association         | no          | YES           |
   *   | stale / unknown UP-SEID     | no          | NEVER         |
   *
   * A stale SEID must never be re-armed: writing bar_state_map for a deleted
   * session would create an entry that nothing deletes.
   *
   * An enqueued report is not re-armed here. The PFCP layer retransmits it;
   * if the SMF never answers, upf_n4::notify_ul_error() asks TASK_UPF_APP to
   * release the latch. If the report is answered, the Session Modification
   * that ends buffering releases it.
   *
   * @param data Start of the record as handed over by libbpf.
   * @param size Record size in bytes, as reserved by the datapath.
   * @return 0 always -- a non-zero return would make ring_buffer__poll()
   *         stop consuming, and no single bad record may stall the ring.
   */
  int HandleEvent(const void* data, size_t size);

  /** @brief libbpf ring_buffer_sample_fn trampoline; @p ctx is `this`. */
  static int OnDdnEvent(void* ctx, void* data, size_t size);

  /** @brief Substitute the SEID resolver (unit tests). */
  void SetCpFseidResolverForTesting(CpFseidResolver resolver);

  /** @brief Substitute the DLDR hand-off (unit tests). */
  void SetDldrDispatcherForTesting(DldrDispatcher dispatcher);

  /** @brief Substitute the latch re-arm (unit tests). */
  void SetBarStateRearmForTesting(BarStateRearm rearm);

  /** @brief Substitute the ring poll (unit tests). */
  void SetRingPollerForTesting(RingPoller poller);

  /**
   * @brief Spawn the poll thread with NO ring attached (unit tests).
   *
   * Start() needs a loaded map, which a host without CAP_BPF does not have.
   * This runs the same PollLoop() as production. Pair it with
   * SetRingPollerForTesting(); without a poller the loop exits at once.
   *
   * @return false if a poll thread is already running or not yet reaped.
   */
  bool StartPollThreadForTesting();

 private:
  /** @brief Publish running_ and spawn the poll thread. Shared by Start() and
   *         StartPollThreadForTesting() so both take the same code path. */
  void StartPollThread();

  /** @brief Poll thread body: poll the ring until Stop() or a fatal error.
   *
   * Clears running_ on the fatal-error exit, so IsRunning() cannot outlive the
   * thread.
   */
  void PollLoop();

  /**
   * @brief Release the one-shot DDN latch after a failed hand-off.
   *
   * @param up_seid UP SEID of a session that RESOLVED a moment ago.
   * @param reason  Why the hand-off failed (log text only).
   */
  void RearmLatch(uint64_t up_seid, const char* reason);

  struct ring_buffer* ring_ = nullptr;
  std::thread poll_thread_;
  std::atomic<bool> running_{false};

  CpFseidResolver resolve_cp_fseid_;
  DldrDispatcher dispatch_dldr_;
  BarStateRearm rearm_bar_state_;
  RingPoller poll_ring_;

  std::atomic<uint64_t> events_received_{0};
  std::atomic<uint64_t> events_malformed_{0};
  std::atomic<uint64_t> events_resolved_{0};
  std::atomic<uint64_t> events_stale_seid_{0};
  std::atomic<uint64_t> events_dispatched_{0};
  std::atomic<uint64_t> events_no_association_{0};
  std::atomic<uint64_t> events_enqueue_failed_{0};
  std::atomic<uint64_t> latch_rearmed_{0};
};

}  // namespace app
}  // namespace upf
}  // namespace oai

#endif  // BAR_DDN_CONSUMER_H_
