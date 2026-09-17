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
 * @brief Polls bar_ddn_ringbuf_map and dispatches the DDN events it carries.
 *
 * Lifecycle -- owned by UserPlaneComponent, so it tracks the eBPF datapath:
 *   Start()  from setup_bpf() (main.cpp), i.e. only when enable_bpf_datapath
 *            is set and only after UserPlaneComponent::Setup() has loaded the
 *            BAR program;
 *   Stop()   FIRST thing in UserPlaneComponent::TearDown(), i.e. BEFORE the
 *            per-session BAR map entries are erased and before the N4 task /
 *            pfcp_switch are destroyed. A poll thread still
 *            running past that point would resolve SEIDs against a freed
 *            pfcp_switch and post to a deleted ITTI.
 *
 * Both are idempotent: TearDown() is reachable twice (SignalHandler and then
 * the singleton destructor at exit()).
 */
class BarDdnConsumer {
 public:
  /** @brief UP SEID -> CP F-SEID resolution.
   *
   * Defaults to the live pfcp_switch (pfcp_switch::get_cp_fseid_by_up_seid,
   * the public accessor added for this consumer). It is a member rather than
   * a direct call so the unit tests can drive the resolved / stale-SEID
   * branches without standing up a pfcp_switch, which owns tun interfaces and
   * worker threads.
   */
  using CpFseidResolver = std::function<bool(uint64_t, pfcp::fseid_t&)>;

  /** @brief DLDR -> TASK_UPF_N4 hand-off.
   *
   * Defaults to the STATIC upf_n4::enqueue_session_report_request(). It
   * deliberately does NOT go through upf_n4_inst: that is the whole point of
   * the function being static, since ~upf_app() deletes upf_n4_inst without
   * nulling it. A member rather than a direct call for the same reason as the
   * resolver: the unit tests drive all three DldrDispatch outcomes without an
   * ITTI, an N4 task or a PFCP association table.
   */
  using DldrDispatcher = std::function<DldrDispatch(
      const pfcp::fseid_t&, const pfcp::pfcp_session_report_request&)>;

  /** @brief Release the kernel one-shot DDN latch of a session.
   *
   * Defaults to SessionProgramManager::ResetBarState() ->
   * BARProgram::ResetBarState() (UPF-T6), which is BPF_EXIST and therefore
   * can only ever overwrite an entry, never create one.
   *
   * @warning Only ever invoked for a session that RESOLVED (i.e. is still
   *          present). A stale UP-SEID must be dropped and counted -- see the
   *          re-arm contract on HandleEvent().
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
   * Defaults to ring_buffer__poll(ring_, timeout_ms), null-guarded on ring_.
   * A member for one reason: the poll loop's FATAL-error exit (the path that
   * must clear running_) is otherwise unreachable in a unit test, because
   * making the real ring_buffer__poll() fail needs a loaded map and CAP_BPF.
   */
  using RingPoller = std::function<int(int)>;

  /** @brief Poll timeout handed to ring_buffer__poll(); bounds shutdown
   *         latency without turning the loop into a spin. */
  static constexpr int kPollTimeoutMs = 200;

  BarDdnConsumer();
  ~BarDdnConsumer();

  BarDdnConsumer(const BarDdnConsumer&) = delete;
  BarDdnConsumer& operator=(const BarDdnConsumer&) = delete;

  /**
   * @brief Attach to the DDN ring and start the poll thread.
   *
   * @param ddn_ringbuf bar_ddn_ringbuf_map, obtained by the caller from
   *        UPF_XDPProgram::GetBarProgram()->GetBarDdnRingbuf(). NOT
   *        GetMapByName(): that helper only knows bar_config_map and
   *        bar_state_map and returns nullptr for the ring.
   * @return true if the poll thread is running.
   *
   * Bails cleanly (logs, returns false, starts no thread) when the map is
   * null, when its fd is negative (unloaded / absent map), or when
   * ring_buffer__new() fails.
   *
   * Restartable: the poll loop can also end by ITSELF on a fatal
   * ring_buffer__poll() error, which leaves a joinable-but-dead thread and an
   * attached ring behind. Start() reaps that corpse (Stop()) before
   * re-attaching, so a restart either really restarts or fails with a logged
   * reason -- it never silently returns "running" while polling nothing.
   */
  bool Start(const std::shared_ptr<BPFMap>& ddn_ringbuf);

  /** @brief Stop and join the poll thread, then free the ring. Idempotent.
   *
   * Safe to call FROM the poll thread: the thread is then detached instead of
   * joined, because joining self throws std::system_error and, on the path
   * that actually does this (SIGSEGV taken ON the poll thread ->
   * SignalHandler::TearDown), the throw would be an uncaught exception inside
   * a signal handler, i.e. std::terminate. See the guard in the definition.
   */
  void Stop();

  /** @brief True while the poll thread is alive.
   *
   * Set by Start(), cleared by Stop() AND by the poll loop itself when
   * ring_buffer__poll() fails fatally -- so a dead consumer never reports
   * healthy.
   */
  bool IsRunning() const;

  /** @brief Current counter values. */
  Counters GetCounters() const;

  /**
   * @brief Handle one ring record.
   *
   * Public because it is the whole decision logic of this class and the unit
   * tests drive it directly; production reaches it through OnDdnEvent().
   *
   * @par Re-arm contract
   * UPF onsumes the kernel latch the instant the event is PRODUCED, so a
   * DDN that is not turned into a report is a downlink burst lost forever
   * unless the latch is released again. Exactly four outcomes:
   *
   *   | outcome                     | report sent | ResetBarState |
   *   |-----------------------------|-------------|---------------|
   *   | enqueued (RETURNok)         | yes (N4)    | NO (see below)|
   *   | ITTI enqueue refused        | no          | YES           |
   *   | no PFCP association         | no          | YES           |
   *   | stale / unknown UP-SEID     | no          | NEVER         |
   *
   * The stale row is structural, not a branch below: the function returns on
   * the !resolved path before any of this runs. It must stay that way -- a
   * write to bar_state_map for a torn-down SEID could resurrect a dead entry
   * that nothing ever deletes again.
   *
   * "NO" on the enqueued row is first of all the approved plan's rule: do not
   * duplicate a report that is already queued. It is now also backed by the
   * transaction layer, which since the H1 fix really does own retransmission
   * on TASK_UPF_N4 -- send_request() arms its retry/cleanup timers with the
   * PFCP_TIMER_ARG1_* sentinels (pfcp.hpp) and upf_n4_task()'s TIME_OUT case
   * routes them to pfcp_l4_stack::time_out_event(), which resends the report
   * up to PFCP_N1_REQUESTS times before giving up. Residual exposure: on
   * give-up notify_ul_error() only logs at TRACE and cannot call back here, so
   * a report lost on all four attempts still leaves the latch consumed and
   * that burst unpaged. See the kEnqueued arm of HandleEvent() for the full
   * note.
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
   * The production entry point is Start(), which needs a loaded map, an fd and
   * ring_buffer__new(); none of that exists on a host without CAP_BPF. This
   * runs the very same PollLoop() through the very same StartPollThread(), so
   * the running_ bookkeeping under test is the shipped one. Pair it with
   * SetRingPollerForTesting(); without a poller the loop exits immediately as
   * if the ring were unusable, and never touches a null ring_.
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
