/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef QOS_MBR_HPP_SEEN
#define QOS_MBR_HPP_SEEN

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace oai::upf {

/**
 * @brief One token bucket: a rate, and how much of a burst is forgiven.
 *
 * It polices rather than shapes: 3GPP TS 29.244 §8.2.8 makes the MBR a
 * ceiling, not a smoothing requirement, so excess is dropped. How much of a
 * burst is forgiven is `qos_burst_ms` -- too little and TCP never reaches its
 * MBR, too much and the MBR itself leaks.
 */
class qos_bucket {
 public:
  qos_bucket(uint64_t rate_bps, uint64_t burst_ms)
      : rate_(rate_bps), burst_(burst_bytes(rate_bps, burst_ms)) {}

  uint64_t rate() const { return rate_; }

  /** @brief Charge `n` bytes; false when the bucket is empty, i.e. over rate.
   *  `now` is passed in so a packet metered against several buckets reads the
   *  clock once. */
  bool pass(uint64_t now, uint64_t n) {
    if (!rate_) return true;
    // Whoever wins this exchange owns the elapsed window and is the only one
    // that credits it; a concurrent metering sees dt 0 and credits nothing,
    // which under-credits -- the safe direction for a limit.
    const uint64_t prev = last_.exchange(now, std::memory_order_relaxed);
    // Clamp the idle window: the bucket cannot hold more than `burst_`
    // anyway, and it stops the multiply below from overflowing.
    uint64_t dt = now > prev ? now - prev : 0;
    if (dt > 1000000000ULL) dt = 1000000000ULL;
    const uint64_t refill = dt * (rate_ / 8) / 1000000000ULL;

    // One QoS flow can carry several inner flows, which the kernel hashes to
    // different tun queues, so two threads can meter one bucket at once. The
    // balance therefore moves with a CAS: a load/store pair lets both threads
    // debit the same credit and each write back its own remainder, so both
    // pass and the bucket runs at twice its rate. The retry recomputes from
    // the fresh balance, so `refill` lands exactly once.
    uint64_t t = tokens_.load(std::memory_order_relaxed);
    uint64_t left;
    bool ok;
    do {
      left = t + refill;
      if (left > burst_) left = burst_;
      ok = left >= n;
      if (ok) left -= n;
    } while (!tokens_.compare_exchange_weak(
        t, left, std::memory_order_relaxed, std::memory_order_relaxed));
    return ok;
  }

 private:
  /// A rate low enough that `burst_ms` of it is under one packet still has to
  /// pass packets, so the window has a floor.
  static uint64_t burst_bytes(uint64_t rate_bps, uint64_t ms) {
    const uint64_t w = rate_bps / 8 * ms / 1000;
    return w > 64 * 1024 ? w : 64 * 1024;
  }

  const uint64_t rate_;   ///< bits/s; 0 means unlimited
  const uint64_t burst_;  ///< bytes
  std::atomic<uint64_t> tokens_{0};
  std::atomic<uint64_t> last_{0};  ///< ns of the previous refill
};

/**
 * @brief QER Maximum Bitrate enforcement (3GPP TS 29.244 §8.2.8).
 *
 * The QoS flow's own MBR bucket, plus the session AMBR bucket behind it,
 * hanging off the PDR the packet matched, so metering costs one clock read and
 * needs no look-up. This replaces programming `tc`, which meant restating the
 * rule on the wire at a hard-coded byte offset and forking /bin/sh per filter
 * on the PFCP path.
 *
 * The session bucket is owned by the pfcp_session and shared by every PDR of
 * that session and direction -- one per PDR would let each PDR pass the whole
 * AMBR on its own, which is not what "session AMBR" means.
 */
class qos_mbr {
 public:
  qos_mbr(
      uint64_t flow_bps, std::shared_ptr<qos_bucket> session, uint64_t burst_ms)
      : flow_(flow_bps, burst_ms), session_(std::move(session)) {}

  /** @brief Same limits? Then keep this meter, and the credit it has built up
   *  -- a Session Modification arrives for every handover and must not reset a
   *  limiter that did not change. */
  bool same_as(
      uint64_t flow_bps, const std::shared_ptr<qos_bucket>& session) const {
    return flow_.rate() == flow_bps && session_ == session;
  }

  /** @brief Meter one packet; false when it is over rate and must be dropped.
   *  A packet has to fit under its own flow's MBR and the session AMBR both.
   *  A packet the flow drops is not charged to the session. */
  bool pass(std::size_t bytes) {
    const uint64_t now =
        (uint64_t) std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();
    return flow_.pass(now, bytes) && (!session_ || session_->pass(now, bytes));
  }

 private:
  qos_bucket flow_;
  std::shared_ptr<qos_bucket> session_;
};

}  // namespace oai::upf

#endif /* QOS_MBR_HPP_SEEN */
