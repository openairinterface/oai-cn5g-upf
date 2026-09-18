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

/// A departure time this far out means the packet cannot be sent at all.
static constexpr uint64_t QOS_TOO_LATE = UINT64_MAX;

/**
 * @brief One rate, as a departure clock (3GPP TS 29.244 §8.2.8).
 *
 * The state is a single timestamp -- the instant this rate's next byte is due
 * -- which is a token bucket written the other way round: a bucket that is
 * `n` bytes short is a clock that is `n / rate` ahead of now. Keeping the time
 * rather than the balance is what lets the same meter both police and shape,
 * because the answer to "may I send this?" and "when may I send this?" is the
 * same number.
 *
 * Either way the clock is advanced by the same amount, so the rate is
 * identical; only the reply differs. Policing answers "now, or never": a
 * packet that would have to wait is dropped, and `tolerance_ms` is how far
 * ahead of real time the clock may run, i.e. the burst. Shaping answers "at
 * this time": the caller holds the packet until then, and `tolerance_ms` is
 * how long it may be held before it is dropped instead, i.e. the queue.
 */
class qos_bucket {
 public:
  qos_bucket(uint64_t rate_bps, uint64_t tolerance_ms, bool shape)
      : rate_(rate_bps),
        // ns per byte in 16.16 fixed point: a multiply and a shift per packet
        // instead of a 64-bit divide.
        ns_per_byte_(rate_bps ? (8000000000ULL << 16) / rate_bps : 0),
        tolerance_(tolerance_ms * 1000000ULL),
        shape_(shape) {}

  uint64_t rate() const { return rate_; }

  /**
   * @brief Reserve this rate's next slot for `n` bytes.
   * @returns 0 to send now, QOS_TOO_LATE to drop, or the time to send at.
   *
   * The reservation is one compare-and-swap, so several threads metering one
   * rate hand out slots in CAS order and never the same slot twice: the
   * aggregate never exceeds the rate however the flows are spread over
   * threads, and no thread has to own the rate.
   */
  uint64_t reserve(uint64_t now, uint64_t n, bool may_wait = true) {
    if (!rate_) return 0;
    const uint64_t cost = (n * ns_per_byte_) >> 16;
    uint64_t tat        = tat_.load(std::memory_order_relaxed);
    uint64_t due;
    do {
      due = tat > now ? tat : now;
      if (due - now > tolerance_) return QOS_TOO_LATE;
      // Nowhere to hold it, so give up before the reservation rather than
      // after: a slot spent on a packet that is then dropped is a slot the
      // next packet does not get, and the rate collapses to whatever fraction
      // of the traffic found a buffer.
      if (shape_ && !may_wait && due > now) return QOS_TOO_LATE;
    } while (!tat_.compare_exchange_weak(
        tat, due + cost, std::memory_order_relaxed, std::memory_order_relaxed));
    return (shape_ && due > now) ? due : 0;
  }

  /** @brief Pull the clock back when the rate changes under a queue, so
   *  packets already waiting are not paced at a rate that no longer applies.
   */
  void clamp(uint64_t now) {
    uint64_t tat = tat_.load(std::memory_order_relaxed);
    while (tat > now + tolerance_ &&
           !tat_.compare_exchange_weak(
               tat, now + tolerance_, std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
  }

 private:
  const uint64_t rate_;         ///< bits/s; 0 means unlimited
  const uint64_t ns_per_byte_;  ///< 16.16 fixed point
  const uint64_t tolerance_;    ///< ns: burst when policing, queue when shaping
  const bool shape_;
  std::atomic<uint64_t> tat_{0};  ///< ns: when this rate's next byte is due
};

/**
 * @brief The two rates a packet has to fit: its QoS flow's MBR, and the
 * session AMBR behind it.
 *
 * Both hang off the PDR the packet matched, so metering costs one clock read
 * and no look-up. The session bucket is owned by the pfcp_session and shared
 * by every PDR of that session and direction -- one per PDR would let each PDR
 * pass the whole AMBR on its own.
 */
class qos_mbr {
 public:
  qos_mbr(
      uint64_t flow_bps, std::shared_ptr<qos_bucket> session,
      uint64_t tolerance_ms, bool shape)
      : flow_(flow_bps, tolerance_ms, shape), session_(std::move(session)) {}

  /** @brief Same limits? Then keep this meter and the credit it has built up
   *  -- a Session Modification arrives for every handover and must not reset a
   *  limiter that did not change. */
  bool same_as(
      uint64_t flow_bps, const std::shared_ptr<qos_bucket>& session) const {
    return flow_.rate() == flow_bps && session_ == session;
  }

  /**
   * @brief Reserve a slot on both rates for one packet.
   * @returns 0 to send now, QOS_TOO_LATE to drop, or the time to send at.
   *
   * A packet the flow rate turns away is not charged to the session.
   */
  uint64_t due_at(std::size_t bytes, bool may_wait = true) {
    const uint64_t now =
        (uint64_t) std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();
    const uint64_t f = flow_.reserve(now, bytes, may_wait);
    if (f == QOS_TOO_LATE || !session_) return f;
    const uint64_t s = session_->reserve(now, bytes, may_wait);
    if (s == QOS_TOO_LATE) return s;
    return f > s ? f : s;  // the later of the two slots
  }

  /** @brief Meter one packet, dropping whatever is over rate. The uplink
   *  polices, so this is all it needs. */
  bool pass(std::size_t bytes) { return due_at(bytes) != QOS_TOO_LATE; }

 private:
  qos_bucket flow_;
  std::shared_ptr<qos_bucket> session_;
};

}  // namespace oai::upf

#endif /* QOS_MBR_HPP_SEEN */
