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
  /**
   * @param took  when non-null, receives the clock this reservation installed,
   *              which is what refund() needs to give it back. Untouched when
   *              the reservation is refused.
   */
  uint64_t reserve(
      uint64_t now, uint64_t n, bool may_wait = true,
      uint64_t* took = nullptr) {
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
    if (took) *took = due + cost;
    return (shape_ && due > now) ? due : 0;
  }

  /** @brief Give back a reservation whose packet was never sent.
   *
   *  Only when ours is still the last one taken, which is what @p took tests:
   *  it is the clock this thread installed, and the compare-and-swap succeeds
   *  only if nothing has reserved since. Subtracting unconditionally would be
   *  wrong -- a reservation is a slot handed to a caller, not a balance, so
   *  winding the clock back past a slot another thread is already holding
   *  hands that same slot to the next caller and two packets depart together.
   *
   *  When the swap fails the reservation stands and the flow is charged for a
   *  packet it did not send. That is the conservative direction: the rate is
   *  never exceeded, only briefly under-used, and only under contention.
   *
   *  @returns true when the slot was given back.
   */
  bool refund(uint64_t took, uint64_t n) {
    if (!rate_) return true;
    uint64_t expected = took;
    return tat_.compare_exchange_strong(
        expected, took - ((n * ns_per_byte_) >> 16), std::memory_order_relaxed,
        std::memory_order_relaxed);
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
   * Neither rate is charged for a packet the other turns away. The flow is
   * reserved first, so when the session AMBR then rejects it the flow's slot
   * is handed back: without that, traffic held down by a congested session
   * AMBR would advance the flow's clock for packets that were never sent, and
   * the flow would settle well below the MBR it was given. The hand-back only
   * takes when no one else has reserved in between -- see refund() -- so it
   * errs towards charging for a packet that was dropped, never towards
   * letting two packets share a slot.
   */
  uint64_t due_at(std::size_t bytes, bool may_wait = true) {
    const uint64_t now =
        (uint64_t) std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();
    uint64_t took    = 0;
    const uint64_t f = flow_.reserve(now, bytes, may_wait, &took);
    if (f == QOS_TOO_LATE || !session_) return f;
    const uint64_t s = session_->reserve(now, bytes, may_wait);
    if (s == QOS_TOO_LATE) {
      flow_.refund(took, bytes);
      return s;
    }
    return f > s ? f : s;  // the later of the two slots
  }

  /** @brief Meter one packet, dropping whatever is over rate. The uplink
   *  polices, so this is all it needs. */
  bool pass(std::size_t bytes) { return due_at(bytes) != QOS_TOO_LATE; }

  /** @brief The flow's own rate, for inspection. Exposed so the accounting
   *  between the two rates can be checked from outside; nothing on the
   *  datapath uses it. */
  qos_bucket& flow() { return flow_; }

 private:
  qos_bucket flow_;
  std::shared_ptr<qos_bucket> session_;
};

}  // namespace oai::upf

#endif /* QOS_MBR_HPP_SEEN */
