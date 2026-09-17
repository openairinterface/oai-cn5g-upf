/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for the reclamation domain. Header-only:
 *
 *   g++ -std=c++17 -O2 -pthread src/upf_app/simpleswitch/test_upf_rcu.cpp \
 *       -o /tmp/test_upf_rcu && /tmp/test_upf_rcu
 *
 * The case that matters is a second domain on a thread that has already read a
 * first one: the thread's slot number has to mean the same thing in both, or
 * the new domain scans nothing and frees memory a reader is still inside.
 */

#include <atomic>
#include <cassert>
#include <cstdio>
#include <memory>
#include <thread>

#include "upf_rcu.hpp"

using oai::upf::rcu_domain;

namespace {

/// A reader inside a critical section holds off reclamation -- in whichever
/// domain it is reading, not just the first one that thread ever read.
void test_second_domain_sees_its_readers() {
  auto first = std::make_unique<rcu_domain>();
  rcu_domain second;
  std::atomic<bool> claimed{false}, go{false};
  std::atomic<bool> inside{false}, may_leave{false}, freed{false};

  // One thread reads both domains, which is the whole point: it caches a slot
  // number while reading the first, and has to be visible in the second under
  // that same number.
  std::thread reader([&] {
    first->read_lock();
    first->read_unlock();
    claimed.store(true);
    while (!go.load()) std::this_thread::yield();
    second.read_lock();
    inside.store(true);
    while (!may_leave.load()) std::this_thread::yield();
    second.read_unlock();
  });

  while (!claimed.load()) std::this_thread::yield();
  first.reset();  // the switch instance that owned it is torn down
  go.store(true);
  while (!inside.load()) std::this_thread::yield();

  second.retire([&] { freed.store(true); });
  second.reclaim();
  assert(!freed.load() && "freed while a reader was still inside");

  may_leave.store(true);
  reader.join();
  second.reclaim();
  assert(freed.load() && "never reclaimed after the reader left");
}

/// Nothing retired is lost when the domain goes away with it.
void test_destructor_runs_deleters() {
  bool freed = false;
  {
    rcu_domain d;
    std::atomic<bool> inside{false}, may_leave{false};
    std::thread reader([&] {
      d.read_lock();
      inside.store(true);
      while (!may_leave.load()) std::this_thread::yield();
      d.read_unlock();
    });
    while (!inside.load()) std::this_thread::yield();
    d.retire([&] { freed = true; });
    assert(!freed && "retired while a reader was inside");
    may_leave.store(true);
    reader.join();
  }
  assert(freed && "deleter lost when the domain was destroyed");
}

/// Slots come back when a thread exits, so a process that runs many
/// short-lived readers -- a test case per thread -- does not run out of them.
void test_slots_are_returned_on_thread_exit() {
  rcu_domain d;
  for (int i = 0; i < rcu_domain::MAX_READERS + 4; i++)
    std::thread([&] {
      d.read_lock();
      d.read_unlock();
    }).join();
  bool freed = false;
  d.retire([&] { freed = true; });
  d.reclaim();
  assert(freed && "a departed thread's slot still looks like a live reader");
}

}  // namespace

int main() {
  test_second_domain_sees_its_readers();
  test_destructor_runs_deleters();
  test_slots_are_returned_on_thread_exit();
  printf("upf_rcu: ok\n");
  return 0;
}
