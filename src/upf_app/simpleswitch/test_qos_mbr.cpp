/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for the MBR meters. Header-only, so it needs nothing but a
 * compiler:
 *
 *   g++ -std=c++17 -O2 -pthread src/upf_app/simpleswitch/test_qos_mbr.cpp \
 *       -o /tmp/test_qos_mbr && /tmp/test_qos_mbr
 *
 * It fails if a bucket passes more than its rate, which is what both the
 * concurrent debit and the shared session bucket are there to prevent.
 */

#include <cassert>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

#include "qos_mbr.hpp"

using oai::upf::qos_bucket;
using oai::upf::qos_mbr;

namespace {

uint64_t now_ns() {
  return (uint64_t) std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

constexpr uint64_t RATE     = 8ULL * 1024 * 1024;  // 1 MB/s
constexpr uint64_t BURST_MS = 1000;                // so burst == 1 MB
constexpr uint64_t BURST    = RATE / 8 * BURST_MS / 1000;
constexpr uint64_t PKT      = 1024;

/// What the bucket may legitimately have passed after running for `ns`.
uint64_t allowance(uint64_t ns) {
  return BURST + (RATE / 8) * ns / 1000000000;
}

/// A bucket is not a free-for-all: an empty one drops.
void test_rate_is_a_ceiling() {
  qos_bucket b(RATE, BURST_MS);
  const uint64_t t0 = now_ns();
  uint64_t passed   = 0;
  for (int i = 0; i < 4096; i++)
    if (b.pass(t0, PKT)) passed += PKT;  // one instant: no refill at all
  assert(passed == BURST && "an idle bucket passes exactly its burst");
}

/// Two threads metering one bucket must not each spend the same credit. With a
/// load/store pair instead of a CAS this passes roughly twice the burst.
void test_no_double_spend() {
  qos_bucket b(RATE, BURST_MS);
  std::atomic<uint64_t> passed{0};
  const uint64_t t0 = now_ns();
  std::vector<std::thread> ts;
  for (int t = 0; t < 8; t++)
    ts.emplace_back([&] {
      uint64_t mine = 0;
      for (int i = 0; i < 8192; i++)
        if (b.pass(now_ns(), PKT)) mine += PKT;
      passed.fetch_add(mine);
    });
  for (auto& t : ts) t.join();
  const uint64_t budget = allowance(now_ns() - t0);
  printf(
      "  concurrent: passed %lu bytes, allowed %lu\n", passed.load(), budget);
  assert(passed.load() <= budget && "bucket passed more than its rate");
}

/// The session AMBR bounds the session, not each PDR: two PDRs sharing it must
/// not each pass the whole allowance.
void test_session_bucket_is_shared() {
  auto session = std::make_shared<qos_bucket>(RATE, BURST_MS);
  qos_mbr pdr1(0, session, BURST_MS);  // no flow MBR, session only
  qos_mbr pdr2(0, session, BURST_MS);
  uint64_t passed = 0;
  for (int i = 0; i < 4096; i++) {
    if (pdr1.pass(PKT)) passed += PKT;
    if (pdr2.pass(PKT)) passed += PKT;
  }
  printf("  shared session: passed %lu bytes, burst %lu\n", passed, BURST);
  assert(passed <= allowance(1000000) && "two PDRs each passed the full AMBR");
}

/// A packet the flow drops must not be charged to the session behind it.
void test_flow_drop_is_not_charged_to_session() {
  auto session = std::make_shared<qos_bucket>(RATE, BURST_MS);
  qos_mbr pdr(RATE / 64, session, BURST_MS);  // a much tighter flow MBR
  for (int i = 0; i < 4096; i++) pdr.pass(PKT);
  // The flow gave up long before the session's burst was spent, so the
  // session still has credit for another PDR.
  qos_mbr other(0, session, BURST_MS);
  assert(other.pass(PKT) && "session charged for packets the flow dropped");
}

}  // namespace

int main() {
  test_rate_is_a_ceiling();
  test_no_double_spend();
  test_session_bucket_is_shared();
  test_flow_drop_is_not_charged_to_session();
  printf("qos_mbr: ok\n");
  return 0;
}
