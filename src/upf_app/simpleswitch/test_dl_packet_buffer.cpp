/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for the DL packet store behind paging. Header-only, so it needs
 * nothing but a compiler:
 *
 *   g++ -std=c++17 -O2 -pthread \
 *       src/upf_app/simpleswitch/test_dl_packet_buffer.cpp \
 *       -o /tmp/test_dl_packet_buffer && /tmp/test_dl_packet_buffer
 *
 * The DN is untrusted, so what has to hold is admission: nothing is held
 * without a record and a current rule, every bound is a hard ceiling however
 * many threads race it, and every packet that got in leaves through exactly
 * one counter.
 *
 * Bounds: see upf_config_yaml.hpp (DL buffering defaults).
 */

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#include "dl_packet_buffer.hpp"

using oai::upf::dl_buffer_limits;
using oai::upf::dl_buffer_stats;
using oai::upf::dl_fifo;
using oai::upf::dl_packet;
using oai::upf::dl_packet_buffer;
using oai::upf::dl_verdict;

namespace {

using clk = dl_packet_buffer::clock;
using std::chrono::milliseconds;

constexpr uint64_t SEID = 0x1001;
constexpr uint64_t UID  = 42;  // an arbitrary rule_uid
constexpr size_t PKT    = 100;

dl_buffer_limits on() {
  dl_buffer_limits l;
  l.enabled = true;
  return l;
}

std::vector<uint8_t> payload(size_t n, uint8_t fill = 0xab) {
  return std::vector<uint8_t>(n, fill);
}

bool put(dl_packet_buffer& b, uint64_t seid, uint64_t uid, size_t n = PKT) {
  const auto p = payload(n);
  return b.enqueue(seid, uid, 7, p.data(), p.size());
}

/// Both closing equations, checked whenever nothing is in flight.
void assert_balanced(const dl_packet_buffer& b) {
  const dl_buffer_stats s = b.stats();
  assert(
      s.stored == s.flushed + s.discarded + s.expired + s.held &&
      "stored != flushed + discarded + expired + held");
  assert(
      s.flushed == s.replay_sent + s.replay_dropped + s.replay_rebuffered &&
      "flushed != replay_sent + replay_dropped + replay_rebuffered");
}

/// Before publish there is no record, so nothing is held -- and no record is
/// created by the attempt.
void test_enqueue_refused_without_record() {
  dl_packet_buffer b(on());
  assert(!put(b, SEID, UID) && "held a packet for an unknown session");
  assert(!b.has_record(SEID) && "an enqueue created a record");
  assert(b.stats().no_record_dropped == 1 && "refusal not counted");
  assert(b.total_pkts() == 0 && b.total_bytes() == 0 && "reservation leaked");

  // With buffering off nothing is held and nothing is counted.
  dl_packet_buffer off;
  off.publish(SEID, {UID});
  assert(!put(off, SEID, UID) && "held a packet with buffering off");
  assert(!off.has_record(SEID) && "publish is not a no-op when off");
  assert(off.stats() == dl_buffer_stats() && "counted with buffering off");
}

/// A uid that is not in `buffering_uids` is refused and leaves the FIFO empty.
void test_stale_uid_opens_no_fifo() {
  dl_packet_buffer b(on());
  b.publish(SEID, {});
  assert(!put(b, SEID, UID) && "held under a uid that does not buffer");
  assert(b.held_for(SEID) == 0 && "a stale uid opened a FIFO");
  assert(b.stats().stale_dropped == 1 && "stale refusal not counted");
  assert(b.session_pkts(SEID) == 0 && b.total_pkts() == 0 && "leaked");
}

/// The per-session packet bound is drop-tail: the first N stay, the rest go.
void test_drop_tail_per_session_pkts() {
  dl_buffer_limits l     = on();
  l.max_pkts_per_session = 4;
  dl_packet_buffer b(l);
  b.publish(SEID, {UID});
  for (int i = 0; i < 4; i++) assert(put(b, SEID, UID) && "under the bound");
  assert(!put(b, SEID, UID) && "over the per-session packet bound");
  assert(b.held_for(SEID) == 4 && "not drop-tail");
  assert(b.stats().overflow_dropped == 1 && "overflow not counted");
  // Another session is not charged for this one.
  b.publish(SEID + 1, {UID});
  assert(put(b, SEID + 1, UID) && "one session's bound refused another");
}

/// Bytes are charged by allocated size, not by payload.
void test_drop_tail_per_session_bytes() {
  dl_buffer_limits l = on();
  const uint32_t c   = dl_packet_buffer::charge_of(PKT);
  assert(c > PKT + dl_packet::HEADROOM && "overhead not charged");
  // Room for three allocations -- but for four payloads.
  l.max_bytes_per_session = 3 * c + c / 2;
  assert(l.max_bytes_per_session >= 4 * PKT && "test sizing");
  dl_packet_buffer b(l);
  b.publish(SEID, {UID});
  for (int i = 0; i < 3; i++) assert(put(b, SEID, UID) && "under the bound");
  assert(!put(b, SEID, UID) && "charged by payload, not allocation");
  assert(b.session_bytes(SEID) == 3ULL * c && "session bytes wrong");
  assert(b.total_bytes() == 3ULL * c && "global bytes wrong");
}

/// The global packet bound holds across sessions.
void test_drop_tail_global_pkts() {
  dl_buffer_limits l = on();
  l.max_pkts_total   = 3;
  dl_packet_buffer b(l);
  for (uint64_t s = 1; s <= 4; s++) b.publish(s, {UID});
  for (uint64_t s = 1; s <= 3; s++) assert(put(b, s, UID) && "under bound");
  assert(!put(b, 4, UID) && "over the global packet bound");
  assert(b.session_pkts(4) == 0 && "per-session share not rolled back");
  assert(b.total_pkts() == 3 && "global count wrong");
}

/// The global byte bound holds across sessions, and a refusal rolls back the
/// packet share it took first.
void test_drop_tail_global_bytes() {
  dl_buffer_limits l = on();
  const uint32_t c   = dl_packet_buffer::charge_of(PKT);
  l.max_bytes_total  = 2 * c + c / 2;
  dl_packet_buffer b(l);
  for (uint64_t s = 1; s <= 3; s++) b.publish(s, {UID});
  assert(put(b, 1, UID) && put(b, 2, UID) && "under the bound");
  assert(!put(b, 3, UID) && "over the global byte bound");
  assert(b.total_pkts() == 2 && "packet share not rolled back");
  assert(b.total_bytes() == 2ULL * c && "byte share wrong");
  assert(b.session_pkts(3) == 0 && "per-session share not rolled back");
}

/// Nothing longer than the receive buffer's payload can be replayed, so it is
/// refused before any reservation; so is an empty packet.
void test_oversize_packet_refused() {
  dl_packet_buffer b(on());
  b.publish(SEID, {UID});
  const uint32_t max = b.limits().max_pkt_len;
  assert(put(b, SEID, UID, max) && "the largest packet refused");
  assert(!put(b, SEID, UID, max + 1) && "an oversize packet admitted");
  assert(!put(b, SEID, UID, 0) && "an empty packet admitted");
  assert(b.held_for(SEID) == 1 && "oversize held");
  assert(b.stats().overflow_dropped == 2 && "oversize not counted");
  assert(b.total_pkts() == 1 && "oversize reserved");
}

/// Many DL threads racing the bounds: never over a ceiling, every attempt
/// counted once, and the reservations all come back.
void test_reserve_rollback_threads() {
  dl_buffer_limits l     = on();
  l.max_pkts_per_session = 50;
  l.max_pkts_total       = 120;
  dl_packet_buffer b(l);
  constexpr int SESSIONS = 4, THREADS = 8, EACH = 200;
  for (uint64_t s = 1; s <= SESSIONS; s++) b.publish(s, {UID});

  std::vector<std::thread> ts;
  for (int t = 0; t < THREADS; t++)
    ts.emplace_back([&b, t] {
      for (int i = 0; i < EACH; i++)
        put(b, 1 + (uint64_t) ((t + i) % SESSIONS), UID);
    });
  for (auto& t : ts) t.join();

  const dl_buffer_stats s = b.stats();
  assert(
      s.stored + s.overflow_dropped == (uint64_t) THREADS * EACH &&
      "an attempt was lost or double counted");
  assert(s.stored <= l.max_pkts_total && "global bound exceeded");
  uint64_t sum = 0;
  for (uint64_t x = 1; x <= SESSIONS; x++) {
    assert(b.held_for(x) <= l.max_pkts_per_session && "session bound exceeded");
    assert(b.session_pkts(x) == b.held_for(x) && "session share leaked");
    sum += b.held_for(x);
  }
  assert(sum == s.stored && b.total_pkts() == sum && "global share leaked");

  for (uint64_t x = 1; x <= SESSIONS; x++)
    b.end_session_modification(x, {}, dl_verdict::discard);
  assert(b.total_pkts() == 0 && b.total_bytes() == 0 && "not released");
  assert_balanced(b);
}

/// The copy keeps the GTP-U headroom in front, and the bytes.
void test_headroom_preserved() {
  dl_packet_buffer b(on());
  b.publish(SEID, {UID});
  std::vector<uint8_t> p(PKT);
  for (size_t i = 0; i < p.size(); i++) p[i] = (uint8_t) i;
  assert(b.enqueue(SEID, UID, 9, p.data(), p.size()) && "refused");
  dl_fifo out = b.end_session_modification(SEID, {}, dl_verdict::flush);
  assert(out.size() == 1 && "not detached");
  const dl_packet& e = out.front();
  assert(e.data() - e.buf.get() == 64 && "headroom lost");
  assert(e.len == PKT && e.pdr_id == 9 && e.rule_uid == UID && "metadata");
  assert(std::memcmp(e.data(), p.data(), PKT) == 0 && "payload changed");
}

/// A Tombstone refuses everything, and gc() erases it only once it is old.
void test_tombstone_refuses_and_gc() {
  dl_packet_buffer b(on());
  b.publish(SEID, {UID});
  assert(put(b, SEID, UID) && put(b, SEID, UID) && "refused");
  const auto t0 = clk::now();
  assert(b.tombstone(SEID, t0) == 2 && "FIFO not discarded");
  assert(b.total_pkts() == 0 && b.total_bytes() == 0 && "not released");
  assert(!put(b, SEID, UID) && "a Tombstone admitted a straggler");
  assert(b.stats().tombstone_dropped == 1 && "straggler not counted");
  assert(b.tombstone(SEID, t0) == 0 && "tombstoned twice");

  assert(b.gc(t0 + milliseconds(999)) == 0 && "collected too early");
  assert(b.has_record(SEID) && "Tombstone gone too early");
  assert(b.gc(t0 + milliseconds(1000)) == 1 && "not collected");
  assert(!b.has_record(SEID) && "Tombstone not erased");
  assert(!put(b, SEID, UID) && b.stats().no_record_dropped == 1 && "gone");
  assert_balanced(b);
}

/// End of a Session Modification on a tombstone neither makes it admit packets
/// again nor returns anything.
void test_detach_on_tombstone_is_noop() {
  dl_packet_buffer b(on());
  b.publish(SEID, {UID});
  b.tombstone(SEID);
  const uint64_t g = b.generation(SEID);
  assert(
      b.end_session_modification(SEID, {UID}, dl_verdict::keep).empty() &&
      "detached from a Tombstone");
  assert(
      b.generation(SEID) == g &&
      "end_session_modification() counted a detach on a tombstoned record");
  assert(
      !put(b, SEID, UID) &&
      "end_session_modification() made a tombstone admit packets");
  // On a missing record it creates nothing.
  assert(
      b.end_session_modification(SEID + 1, {UID}, dl_verdict::flush).empty() &&
      "end_session_modification() returned packets for a missing record");
  assert(!b.has_record(SEID + 1) && "detach created a record");
}

/// A late publish cannot bring a Tombstone back to life.
void test_publish_on_tombstone_is_noop() {
  dl_packet_buffer b(on());
  b.publish(SEID, {});
  b.tombstone(SEID);
  b.publish(SEID, {UID});
  assert(
      b.is_tombstone(SEID) &&
      "publish turned a tombstone back into an Active record");
  assert(!put(b, SEID, UID) && "publish made a Tombstone admit");
}

/// The maximum hold time discards FIFOs whose oldest packet has waited long
/// enough, and returns each PDR ID once, so that the caller can re-arm those
/// PDRs; younger FIFOs stay, and so does the buffering period.
void test_expire_returns_pdr_ids() {
  dl_packet_buffer b(on());
  const auto t0 = clk::now();
  const auto p  = payload(PKT);
  b.publish(1, {10, 11});
  b.publish(2, {20});
  assert(b.enqueue(1, 10, 1, p.data(), PKT, t0) && "refused");
  assert(
      b.enqueue(1, 11, 2, p.data(), PKT, t0 + milliseconds(5)) &&
      "packet of PDR 2 refused");
  assert(
      b.enqueue(1, 10, 1, p.data(), PKT, t0 + milliseconds(6)) &&
      "second packet of PDR 1 refused");
  assert(
      b.enqueue(2, 20, 1, p.data(), PKT, t0 + milliseconds(500)) &&
      "packet of session 2 refused");

  assert(
      b.expire(t0 + milliseconds(999), milliseconds(1000)).empty() &&
      "a FIFO expired before the maximum hold time");
  auto x = b.expire(t0 + milliseconds(1000), milliseconds(1000));
  assert(x.size() == 1 && x[0].seid == 1 && "wrong FIFO expired");
  assert(x[0].discarded == 3 && "whole FIFO not discarded");
  assert(
      x[0].pdr_ids.size() == 2 &&
      ((x[0].pdr_ids[0] == 1 && x[0].pdr_ids[1] == 2) ||
       (x[0].pdr_ids[0] == 2 && x[0].pdr_ids[1] == 1)) &&
      "PDR IDs not returned once each");
  assert(b.held_for(1) == 0 && b.held_for(2) == 1 && "wrong FIFO emptied");
  assert(b.stats().expired == 3 && "expired not counted");
  assert(b.session_pkts(1) == 0 && "not released");
  // The buffering period goes on: the next packet is held again.
  assert(put(b, 1, 10) && "expiry ended the buffering period");
  assert_balanced(b);
}

/// A Downlink Data Report that could not be queued is retried once per take:
/// deduplicated, drained whole, and dropped when the session is gone.
void test_report_retry_once_per_take() {
  dl_packet_buffer b(on());
  b.publish(1, {10});
  b.publish(2, {20});
  // true means "the notification latch may stay set": a mark is stored, or
  // none is needed. Only an allocation failure returns false.
  bool held = b.mark_report_failed(1, 1);
  assert(held && "first mark refused");
  held = b.mark_report_failed(1, 1);
  assert(held && "duplicate mark refused");
  b.mark_report_failed(2, 2);
  auto r = b.take_report_retries();
  assert(r.size() == 2 && "not deduplicated per (seid, PDR ID)");
  assert(b.take_report_retries().empty() && "not drained");

  // Marks on a missing record are dropped with buffering on...
  held = b.mark_report_failed(99, 0);
  assert(held && "caller told to re-arm for a missing record");
  assert(b.take_report_retries().empty() && "mark kept for a missing record");
  // ...on a Tombstone, and by tombstone() itself.
  b.mark_report_failed(1, 1);
  b.tombstone(1);
  held = b.mark_report_failed(1, 1);
  assert(held && "caller told to re-arm on a tombstone");
  assert(b.take_report_retries().empty() && "mark kept on a Tombstone");
  // Nothing is left for a SEID once tombstone() and gc() are through with it.
  b.mark_report_failed(2, 2);
  b.tombstone(2, clk::now() - milliseconds(2000));
  b.gc(clk::now());
  assert(b.take_report_retries().empty() && "mark survived gc");

  // With buffering off there are no records, and the marks still work.
  dl_packet_buffer off;
  held = off.mark_report_failed(5, 5);
  assert(held && "mark refused with buffering off");
  off.mark_report_failed(5, 5);
  r = off.take_report_retries();
  assert(
      r.size() == 1 && r[0].seid == 5 && r[0].pdr_id == 5 &&
      "mark lost with buffering off");
  assert(off.take_report_retries().empty() && "not drained with buffering off");
}

/// Every packet that got in leaves through exactly one counter.
void test_counters_balance() {
  dl_packet_buffer b(on());
  b.publish(1, {10});
  b.publish(2, {20});
  b.publish(3, {30});
  b.publish(4, {40});
  for (int i = 0; i < 3; i++) put(b, 1, 10);
  for (int i = 0; i < 2; i++) put(b, 2, 20);
  put(b, 3, 30, PKT);
  const auto p = payload(PKT);
  b.enqueue(4, 40, 1, p.data(), PKT, clk::now() - milliseconds(30000));
  put(b, 1, 99);  // stale: counted, not stored
  assert_balanced(b);

  dl_fifo f = b.end_session_modification(1, {}, dl_verdict::flush);
  b.note_replay(oai::upf::dl_outcome::sent);
  b.note_replay(oai::upf::dl_outcome::dropped);
  b.note_replay(oai::upf::dl_outcome::rebuffered);
  assert(f.size() == 3 && "flush");
  b.end_session_modification(2, {}, dl_verdict::discard);
  b.tombstone(3);
  b.expire(clk::now(), milliseconds(20000));
  const dl_buffer_stats s = b.stats();
  assert(s.flushed == 3 && s.discarded == 3 && s.expired == 1 && "counters");
  assert(s.held == 0 && b.total_pkts() == 0 && "held after everything left");
  assert_balanced(b);
}

}  // namespace

int main() {
  test_enqueue_refused_without_record();
  test_stale_uid_opens_no_fifo();
  test_drop_tail_per_session_pkts();
  test_drop_tail_per_session_bytes();
  test_drop_tail_global_pkts();
  test_drop_tail_global_bytes();
  test_oversize_packet_refused();
  test_reserve_rollback_threads();
  test_headroom_preserved();
  test_tombstone_refuses_and_gc();
  test_detach_on_tombstone_is_noop();
  test_publish_on_tombstone_is_noop();
  test_expire_returns_pdr_ids();
  test_report_retry_once_per_take();
  test_counters_balance();
  printf("dl_packet_buffer: ok\n");
  return 0;
}
