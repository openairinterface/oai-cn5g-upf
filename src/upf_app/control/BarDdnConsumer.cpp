/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "BarDdnConsumer.h"

#include <arpa/inet.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <cstring>
#include <thread>
#include <utility>

#include "SessionProgramManager.h"
#include "common_root_types.h"
#include "logger.hpp"
#include "pfcp_switch.hpp"
#include "upf_dldr_report.hpp"
#include "upf_n4.hpp"
#include "wrappers/BPFMap.hpp"

extern oai::upf::app::pfcp_switch* pfcp_switch_inst;

namespace oai {
namespace upf {
namespace app {

namespace {

/** @brief Render evt.ue_ip for logging.
 *
 * packet_context::ue_ip is HOST byte order on the downlink entry path
 * (xdp_n6_entry_kern.c does `bpf_ntohl(ip->daddr)` before storing it) and
 * bar_submit_ddn() copies it verbatim, so put it back on the wire before
 * formatting.
 */
std::string FormatUeIpv4(uint32_t ue_ip_hbo) {
  struct in_addr addr;
  addr.s_addr               = htonl(ue_ip_hbo);
  char buf[INET_ADDRSTRLEN] = {};
  if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) return "?";
  return std::string(buf);
}

}  // namespace

//------------------------------------------------------------------------------
BarDdnConsumer::BarDdnConsumer()
    : resolve_cp_fseid_([](uint64_t up_seid, pfcp::fseid_t& out) {
        if (!pfcp_switch_inst) return false;
        return pfcp_switch_inst->get_cp_fseid_by_up_seid(up_seid, out);
      }),
      dispatch_dldr_([](const pfcp::fseid_t& cp_fseid,
                        const pfcp::pfcp_session_report_request& report) {
        // Send an itti_n4_session_report_request message to Task UPF N4
        bool association_found = false;
        if (upf_n4::enqueue_session_report_request(
                cp_fseid, report, association_found)) {
          return DldrDispatch::kEnqueued;
        }
        return association_found ? DldrDispatch::kEnqueueFailed :
                                   DldrDispatch::kNoAssociation;
      }),
      rearm_bar_state_([](uint64_t up_seid) {
        return SessionProgramManager::GetInstance().ResetBarState(up_seid);
      }),
      poll_ring_([this](int timeout_ms) {
        // ring_buffer__poll() dereferences its first argument, so never call
        // it without a ring. ring_ is written only before the thread is
        // spawned and after it is joined, so this read is not concurrent.
        if (!ring_) return -EINVAL;
        return ring_buffer__poll(ring_, timeout_ms);
      }) {}

//------------------------------------------------------------------------------
BarDdnConsumer::~BarDdnConsumer() {
  Stop();
}

//------------------------------------------------------------------------------
void BarDdnConsumer::SetCpFseidResolverForTesting(CpFseidResolver resolver) {
  resolve_cp_fseid_ = std::move(resolver);
}

//------------------------------------------------------------------------------
void BarDdnConsumer::SetDldrDispatcherForTesting(DldrDispatcher dispatcher) {
  dispatch_dldr_ = std::move(dispatcher);
}

//------------------------------------------------------------------------------
void BarDdnConsumer::SetBarStateRearmForTesting(BarStateRearm rearm) {
  rearm_bar_state_ = std::move(rearm);
}

//------------------------------------------------------------------------------
void BarDdnConsumer::SetRingPollerForTesting(RingPoller poller) {
  poll_ring_ = std::move(poller);
}

//------------------------------------------------------------------------------
bool BarDdnConsumer::StartPollThreadForTesting() {
  if (IsRunning() || poll_thread_.joinable()) return false;
  StartPollThread();
  return true;
}

//------------------------------------------------------------------------------
bool BarDdnConsumer::IsRunning() const {
  return running_.load(std::memory_order_acquire);
}

//------------------------------------------------------------------------------
BarDdnConsumer::Counters BarDdnConsumer::GetCounters() const {
  Counters c;
  c.received       = events_received_.load(std::memory_order_relaxed);
  c.malformed      = events_malformed_.load(std::memory_order_relaxed);
  c.resolved       = events_resolved_.load(std::memory_order_relaxed);
  c.stale_seid     = events_stale_seid_.load(std::memory_order_relaxed);
  c.dispatched     = events_dispatched_.load(std::memory_order_relaxed);
  c.no_association = events_no_association_.load(std::memory_order_relaxed);
  c.enqueue_failed = events_enqueue_failed_.load(std::memory_order_relaxed);
  c.rearmed        = latch_rearmed_.load(std::memory_order_relaxed);
  return c;
}

//------------------------------------------------------------------------------
bool BarDdnConsumer::Start(const std::shared_ptr<BPFMap>& ddn_ringbuf) {
  if (IsRunning()) {
    Logger::upf_app().warn("DDN ring-buffer consumer is already running");
    return true;
  }

  /*
   * Not running, but possibly not reaped either: PollLoop() also exits on its
   * OWN on a fatal ring_buffer__poll() error, and it clears running_ when it
   * does. What it leaves behind is a joinable-but-dead std::thread and an
   * attached ring. Assigning over a joinable std::thread calls
   * std::terminate(), so reap here rather than in the caller -- Stop() joins
   * the finished thread and frees the old ring, both no-ops if there is
   * nothing to reap.
   */
  if (poll_thread_.joinable() || ring_) {
    Logger::upf_app().warn(
        "DDN ring-buffer consumer: a previous poll thread ended on its own "
        "-- reaping it before re-attaching");
    Stop();
  }

  if (!ddn_ringbuf) {
    Logger::upf_app().error(
        "DDN ring-buffer consumer NOT started: bar_ddn_ringbuf_map is null "
        "-- network-triggered paging will not work");
    return false;
  }

  const int rb_fd = ddn_ringbuf->GetFd();
  if (rb_fd < 0) {
    Logger::upf_app().error(
        "DDN ring-buffer consumer NOT started: map '%s' has no fd (%d) "
        "-- not loaded? network-triggered paging will not work",
        ddn_ringbuf->GetName().c_str(), rb_fd);
    return false;
  }

  errno = 0;
  ring_ = ring_buffer__new(rb_fd, &BarDdnConsumer::OnDdnEvent, this, nullptr);
  if (!ring_) {
    Logger::upf_app().error(
        "DDN ring-buffer consumer NOT started: ring_buffer__new(fd=%d) failed "
        "errno=%d (%s)",
        rb_fd, errno, strerror(errno));
    return false;
  }

  StartPollThread();

  Logger::upf_app().info(
      "DDN ring-buffer consumer started on '%s' (fd=%d, poll timeout %d ms)",
      ddn_ringbuf->GetName().c_str(), rb_fd, kPollTimeoutMs);
  return true;
}

//------------------------------------------------------------------------------
void BarDdnConsumer::StartPollThread() {
  running_.store(true, std::memory_order_release);
  poll_thread_ = std::thread(&BarDdnConsumer::PollLoop, this);
}

//------------------------------------------------------------------------------
void BarDdnConsumer::Stop() {
  const bool was_running = running_.exchange(false, std::memory_order_acq_rel);

  if (poll_thread_.joinable()) {
    if (poll_thread_.get_id() == std::this_thread::get_id()) {
      Logger::upf_app().warn(
          "DDN ring-buffer consumer stopped FROM ITS OWN poll thread "
          "(fault/signal on the poll thread?) -- detaching instead of joining");
      poll_thread_.detach();
    } else {
      poll_thread_.join();
    }
  }

  if (ring_) {
    ring_buffer__free(ring_);
    ring_ = nullptr;
  }

  if (was_running) {
    const Counters c = GetCounters();
    Logger::upf_app().info(
        "DDN ring-buffer consumer stopped (received=%lu, malformed=%lu, "
        "resolved=%lu, stale_seid=%lu, dispatched=%lu, no_association=%lu, "
        "enqueue_failed=%lu, rearmed=%lu)",
        c.received, c.malformed, c.resolved, c.stale_seid, c.dispatched,
        c.no_association, c.enqueue_failed, c.rearmed);
  }
}

//------------------------------------------------------------------------------
void BarDdnConsumer::PollLoop() {
  Logger::upf_app().debug("DDN ring-buffer poll thread running");

  while (running_.load(std::memory_order_acquire)) {
    const int ret = poll_ring_ ? poll_ring_(kPollTimeoutMs) : -EINVAL;
    if (ret < 0) {
      if (ret == -EINTR) continue;  // signal during epoll_wait, not an error
      Logger::upf_app().error(
          "DDN ring-buffer poll failed (ret=%d) -- poll thread exiting, "
          "network-triggered paging stops here",
          ret);
      running_.store(false, std::memory_order_release);
      break;
    }
  }

  Logger::upf_app().debug("DDN ring-buffer poll thread exited");
}

//------------------------------------------------------------------------------
int BarDdnConsumer::OnDdnEvent(void* ctx, void* data, size_t size) {
  auto* self = static_cast<BarDdnConsumer*>(ctx);
  if (!self) return 0;
  return self->HandleEvent(data, size);
}

//------------------------------------------------------------------------------
int BarDdnConsumer::HandleEvent(const void* data, size_t size) {
  if (!data || size < sizeof(struct bar_ddn_event)) {
    events_malformed_.fetch_add(1, std::memory_order_relaxed);
    Logger::upf_app().error(
        "DDN event dropped: short record (%zu bytes, expected >= %zu) -- "
        "kernel/userspace bar_ddn_event layout drift?",
        size, sizeof(struct bar_ddn_event));
    return 0;
  }

  struct bar_ddn_event evt = {};
  std::memcpy(&evt, data, sizeof(evt));
  events_received_.fetch_add(1, std::memory_order_relaxed);

  const std::string ue_ip = FormatUeIpv4(evt.ue_ip);

  pfcp::fseid_t cp_fseid = {};
  const bool resolved =
      resolve_cp_fseid_ && resolve_cp_fseid_(evt.seid, cp_fseid);

  if (!resolved) {
    const uint64_t stale =
        events_stale_seid_.fetch_add(1, std::memory_order_relaxed) + 1;
    Logger::upf_app().warn(
        "DDN event dropped: UP-SEID " SEID_FMT
        " unknown (session torn down?) -- BAR-ID=%u PDR-ID=%u UE-IP=%s "
        "ts=%lu ns; not re-armed (stale_seid=%lu)",
        evt.seid, evt.bar_id, evt.pdr_id, ue_ip.c_str(),
        static_cast<uint64_t>(evt.timestamp_ns), stale);
    return 0;
  }

  events_resolved_.fetch_add(1, std::memory_order_relaxed);

  Logger::upf_app().info(
      "DDN event: UP-SEID " SEID_FMT " -> CP-F-SEID " SEID_FMT
      " BAR-ID=%u PDR-ID=%u UE-IP=%s ts=%lu ns",
      evt.seid, cp_fseid.seid, evt.bar_id, evt.pdr_id, ue_ip.c_str(),
      static_cast<uint64_t>(evt.timestamp_ns));

  // Make a DLDR report
  pfcp::pdr_id_t pdr_id = {};
  pdr_id.rule_id        = static_cast<uint16_t>(evt.pdr_id);

  const pfcp::pfcp_session_report_request report = make_dldr_report(pdr_id);

  const DldrDispatch outcome = dispatch_dldr_ ?
                                   dispatch_dldr_(cp_fseid, report) :
                                   DldrDispatch::kEnqueueFailed;

  switch (outcome) {
    case DldrDispatch::kEnqueued:
      events_dispatched_.fetch_add(1, std::memory_order_relaxed);
      Logger::upf_app().info(
          "DLDR queued on TASK_UPF_N4: CP-F-SEID " SEID_FMT
          " PDR-ID=%u "
          "(UP-SEID " SEID_FMT ", UE-IP=%s)",
          cp_fseid.seid, pdr_id.rule_id, evt.seid, ue_ip.c_str());
      break;

    case DldrDispatch::kNoAssociation:
      events_no_association_.fetch_add(1, std::memory_order_relaxed);
      Logger::upf_app().warn(
          "DLDR NOT sent: no PFCP association for CP-F-SEID " SEID_FMT
          " (UP-SEID " SEID_FMT ", PDR-ID=%u)",
          cp_fseid.seid, evt.seid, pdr_id.rule_id);
      RearmLatch(evt.seid, "no PFCP association");
      break;

    case DldrDispatch::kEnqueueFailed:
      events_enqueue_failed_.fetch_add(1, std::memory_order_relaxed);
      Logger::upf_app().error(
          "DLDR NOT queued on TASK_UPF_N4 for CP-F-SEID " SEID_FMT
          " (UP-SEID " SEID_FMT ", PDR-ID=%u)",
          cp_fseid.seid, evt.seid, pdr_id.rule_id);
      RearmLatch(evt.seid, "ITTI enqueue refused");
      break;
  }

  return 0;
}

//------------------------------------------------------------------------------
void BarDdnConsumer::RearmLatch(uint64_t up_seid, const char* reason) {
  latch_rearmed_.fetch_add(1, std::memory_order_relaxed);

  if (!rearm_bar_state_) {
    Logger::upf_app().error(
        "Cannot re-arm the DDN latch of UP-SEID " SEID_FMT
        " (%s): no re-arm hook -- this downlink burst is lost",
        up_seid, reason);
    return;
  }

  const bool cleared = rearm_bar_state_(up_seid);
  Logger::upf_app().info(
      "Re-armed the DDN latch of UP-SEID " SEID_FMT " after %s (%s)", up_seid,
      reason,
      cleared ? "latch cleared, next DL packet re-triggers" :
                "no bar_state entry -- session gone or never latched");
}

}  // namespace app
}  // namespace upf
}  // namespace oai
