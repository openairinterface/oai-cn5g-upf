/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for the MBR meters. Header-only, so it needs nothing but a
 * compiler:
 *
 *   g++ -std=c++17 -O2 -pthread src/upf_app/simpleswitch/test_qos_mbr.cpp \
 *       -o /tmp/test_qos_mbr && /tmp/test_qos_mbr
 *
 * It fails if a rate carries more than it should -- whether it polices, where
 * the excess is dropped, or shapes, where it is given a later slot.
 */

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

#include "qos_mbr.hpp"

using oai::upf::qos_bucket;
using oai::upf::qos_mbr;
using oai::upf::QOS_TOO_LATE;

namespace {

uint64_t now_ns() {
  return (uint64_t) std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

constexpr uint64_t RATE    = 8ULL * 1024 * 1024;  // 1 MB/s
constexpr uint64_t TOL_MS  = 1000;
constexpr uint64_t TOL_NS  = TOL_MS * 1000000ULL;
constexpr uint64_t PKT     = 1024;
constexpr uint64_t COST_NS = PKT * 8 * 1000000000ULL / RATE;  // ns per packet

/// Policing: the clock may run `tolerance` ahead of now and no further, which
/// is a burst of tolerance x rate and then nothing.
void test_policing_is_a_ceiling() {
  qos_bucket b(RATE, TOL_MS, false);
  const uint64_t t0 = now_ns();
  uint64_t passed   = 0;
  for (int i = 0; i < 4096; i++)
    if (b.reserve(t0, PKT) != QOS_TOO_LATE) passed += PKT;  // one instant
  const uint64_t burst = RATE / 8 * TOL_MS / 1000;
  assert(passed >= burst && passed <= burst + PKT && "burst is not the rate");
}

/// Shaping: nothing is dropped inside the horizon; every packet comes back
/// with a slot, and the slots are spaced by the cost of a packet.
void test_shaping_spaces_the_slots() {
  qos_bucket b(RATE, TOL_MS, true);
  const uint64_t t0 = now_ns();
  uint64_t last = 0, n = 0;
  for (int i = 0; i < 512; i++) {
    const uint64_t due = b.reserve(t0, PKT);
    if (due == QOS_TOO_LATE) break;
    if (due) {  // 0 means "send now", which only the first packet gets
      assert(due >= last && "slots handed out out of order");
      if (last) {
        const uint64_t gap = due - last;
        assert(gap >= COST_NS - 1 && gap <= COST_NS + 1 && "wrong spacing");
      }
      last = due;
      n++;
    }
  }
  assert(n > 1 && "nothing was shaped");
  printf(
      "  shaping: %lu slots, %lu ns apart, cost %lu ns\n", n,
      last ? COST_NS : 0, COST_NS);
}

/// ... and a packet whose slot is past the horizon is still dropped, or the
/// queue would be unbounded.
void test_shaping_still_drops_past_the_horizon() {
  qos_bucket b(RATE, TOL_MS, true);
  const uint64_t t0 = now_ns();
  uint64_t held     = 0;
  for (int i = 0; i < 100000; i++) {
    const uint64_t due = b.reserve(t0, PKT);
    if (due == QOS_TOO_LATE) {
      assert(held * COST_NS >= TOL_NS - COST_NS && "gave up too early");
      printf("  horizon: %lu packets held, then dropped\n", held);
      return;
    }
    held++;
  }
  assert(false && "the queue never filled: the horizon is not enforced");
}

/// Several threads metering one rate hand out each slot once. With a load and
/// a store in place of the CAS, two of them take the same slot.
void test_no_double_reservation() {
  qos_bucket b(RATE, TOL_MS, false);
  std::atomic<uint64_t> passed{0};
  const uint64_t t0 = now_ns();
  std::vector<std::thread> ts;
  for (int t = 0; t < 8; t++)
    ts.emplace_back([&] {
      uint64_t mine = 0;
      for (int i = 0; i < 8192; i++)
        if (b.reserve(now_ns(), PKT) != QOS_TOO_LATE) mine += PKT;
      passed.fetch_add(mine);
    });
  for (auto& t : ts) t.join();
  const uint64_t budget =
      RATE / 8 * TOL_MS / 1000 + (RATE / 8) * (now_ns() - t0) / 1000000000;
  printf(
      "  concurrent: passed %lu bytes, allowed %lu (%.1f%%)\n", passed.load(),
      budget, 100.0 * (double) passed.load() / (double) budget);
  fflush(stdout);
  // The margin covers the clock each thread reads for itself: one that reads
  // `now` a moment later is entitled to a moment more rate. A lost CAS would
  // hand out the same slot twice and show up as twice the rate, not a few
  // percent.
  assert(
      passed.load() <= budget + budget / 20 && "a slot was handed out twice");
}

/// The session AMBR bounds the session, not each PDR: two PDRs sharing it must
/// not each pass the whole allowance.
void test_session_bucket_is_shared() {
  auto session = std::make_shared<qos_bucket>(RATE, TOL_MS, false);
  qos_mbr pdr1(0, session, TOL_MS, false);  // no flow MBR, session only
  qos_mbr pdr2(0, session, TOL_MS, false);
  uint64_t passed = 0;
  for (int i = 0; i < 4096; i++) {
    if (pdr1.pass(PKT)) passed += PKT;
    if (pdr2.pass(PKT)) passed += PKT;
  }
  const uint64_t burst = RATE / 8 * TOL_MS / 1000;
  printf("  shared session: passed %lu bytes, burst %lu\n", passed, burst);
  assert(passed <= burst + burst / 10 && "two PDRs each passed the full AMBR");
}

/// A packet the flow rate turns away must not be charged to the session.
void test_flow_drop_is_not_charged_to_session() {
  auto session = std::make_shared<qos_bucket>(RATE, TOL_MS, false);
  qos_mbr pdr(RATE / 64, session, TOL_MS, false);  // a much tighter flow MBR
  for (int i = 0; i < 4096; i++) pdr.pass(PKT);
  qos_mbr other(0, session, TOL_MS, false);
  assert(other.pass(PKT) && "session charged for packets the flow dropped");
}

/// A packet that cannot be held must not take a slot on the way out, or the
/// rate is spent on packets nobody will ever send.
void test_no_room_does_not_spend_the_rate() {
  qos_bucket b(RATE, TOL_MS, true);
  const uint64_t t0 = now_ns();
  b.reserve(t0, PKT);  // the first is due now; the clock is now ahead
  uint64_t refused = 0;
  for (int i = 0; i < 64; i++)
    if (b.reserve(t0, PKT, false) == QOS_TOO_LATE) refused++;
  assert(refused == 64 && "queued a packet with nowhere to put it");
  // The clock only moved for the one packet that was really taken, so the
  // capacity is still there for whoever can hold it.
  assert(
      b.reserve(t0, PKT) == t0 + COST_NS &&
      "the rate was spent on packets that were dropped");
}

/// A reservation handed back has to leave the clock where it was, or the slot
/// it gave up is lost and the rate settles below what was configured.
void test_refund_returns_the_slot() {
  qos_bucket b(RATE, TOL_MS, true);  // shaping, so the reply is the due time
  const uint64_t t0 = now_ns();
  uint64_t took     = 0;
  assert(b.reserve(t0, PKT, true, &took) == 0 && "the first packet is due now");
  assert(
      b.reserve(t0, PKT, true, &took) == t0 + COST_NS &&
      "the second is one cost later");
  assert(b.refund(took, PKT) && "nothing had reserved since, so give it back");
  assert(
      b.reserve(t0, PKT) == t0 + COST_NS &&
      "a refunded slot was not handed back");
}

/// A refund must never wind the clock back past a slot somebody else is
/// already holding: that hands the same slot out twice and two packets leave
/// together, which is the rate exceeded. A blind subtraction does exactly
/// that, so the refund only takes when our reservation is still the last one.
void test_refund_does_not_reissue_a_taken_slot() {
  qos_bucket b(RATE, TOL_MS, true);
  const uint64_t t0 = now_ns();
  uint64_t first = 0, second = 0;
  const uint64_t s1 = b.reserve(t0, PKT, true, &first);   // slot now
  const uint64_t s2 = b.reserve(t0, PKT, true, &second);  // slot t0 + 1c
  (void) s1;
  // The first packet is rejected by the other meter, but the second has
  // already been handed t0 + 1c. Its slot is not ours to give away.
  assert(
      !b.refund(first, PKT) &&
      "refunded a reservation that was no longer the last one");
  // So the next caller gets the slot after the second, never the second's.
  const uint64_t s3 = b.reserve(t0, PKT);
  assert(s3 != s2 && "the same slot was handed out twice");
  assert(s3 == t0 + 2 * COST_NS && "the clock did not move on by one cost");
}

/// The same thing under real contention: many threads reserving, each giving
/// its slot back, and no two packets may ever be told to leave at the same
/// instant.
void test_concurrent_refund_keeps_slots_unique() {
  constexpr int THREADS = 8;
  constexpr int ITERS   = 2048;
  // A tolerance wide enough that nothing is refused, so every loop is a
  // reserve and a refund racing each other.
  qos_bucket b(RATE, 600 * 1000, true);
  const uint64_t t0 = now_ns();
  std::vector<std::vector<uint64_t>> kept(THREADS);
  std::vector<std::thread> ts;
  for (int t = 0; t < THREADS; t++) {
    ts.emplace_back([&, t] {
      for (int i = 0; i < ITERS; i++) {
        uint64_t took       = 0;
        const uint64_t slot = b.reserve(t0, PKT, true, &took);
        if (slot == QOS_TOO_LATE) continue;
        // Every other packet is "rejected by the session" and handed back.
        if (i % 2 == 0 && b.refund(took, PKT)) continue;
        kept[t].push_back(slot);
      }
    });
  }
  for (auto& th : ts) th.join();

  std::vector<uint64_t> all;
  for (auto& v : kept) all.insert(all.end(), v.begin(), v.end());
  std::sort(all.begin(), all.end());
  // Slot 0 is reported as "send now", so several may legitimately share it;
  // every later slot is a distinct departure time.
  size_t dup = 0;
  for (size_t i = 1; i < all.size(); i++)
    if (all[i] == all[i - 1] && all[i] != 0) dup++;
  assert(dup == 0 && "a refund handed the same departure slot out twice");
}

/// The mirror of test_flow_drop_is_not_charged_to_session: a packet the
/// session AMBR turns away must not advance the flow's clock either. Both
/// clocks stop at the same horizon, so this asks the flow directly rather than
/// trying to tell them apart through pass().
void test_session_drop_is_not_charged_to_flow() {
  // A session 64x tighter than the flow: it is the binding constraint, and
  // almost every packet offered is refused by it, not by the flow.
  auto session = std::make_shared<qos_bucket>(RATE / 64, TOL_MS, false);
  qos_mbr pdr(RATE, session, TOL_MS, false);

  constexpr int ATTEMPTS = 2048;
  size_t passed          = 0;
  for (int i = 0; i < ATTEMPTS; i++)
    if (pdr.pass(PKT)) passed++;
  assert(passed > 0 && "the session refused everything");
  assert(
      passed < ATTEMPTS / 8 && "the session was meant to be the tighter one");

  // The flow sent `passed` packets, so that is all its clock may have moved:
  // its burst is still there for whoever wants it. Charged for every refused
  // packet as well it would be sitting on the horizon with nothing left.
  const uint64_t burst = TOL_NS / COST_NS;
  size_t room          = 0;
  const uint64_t t     = now_ns();
  while (pdr.flow().reserve(t, PKT) != QOS_TOO_LATE) room++;
  assert(
      room > burst - passed - 2 &&
      "the flow was charged for packets the session AMBR dropped");
}

}  // namespace

int main() {
  test_refund_returns_the_slot();
  test_refund_does_not_reissue_a_taken_slot();
  test_concurrent_refund_keeps_slots_unique();
  test_session_drop_is_not_charged_to_flow();
  test_no_room_does_not_spend_the_rate();
  test_policing_is_a_ceiling();
  test_shaping_spaces_the_slots();
  test_shaping_still_drops_past_the_horizon();
  test_no_double_reservation();
  test_session_bucket_is_shared();
  test_flow_drop_is_not_charged_to_session();
  printf("qos_mbr: ok\n");
  return 0;
}
