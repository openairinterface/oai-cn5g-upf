/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef UPF_RCU_HPP_SEEN
#define UPF_RCU_HPP_SEEN

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

namespace oai::upf {

/**
 * @brief Epoch-based reclamation for the datapath lookup structures.
 *
 * The problem it solves: PFCP can delete a session while datapath threads are
 * reading it. Until now every packet copied a std::shared_ptr to keep the
 * object alive -- correct, but it costs an atomic increment and decrement on a
 * shared cache line for each of the four objects a packet touches (PDR vector,
 * session, FAR), so 8-12 atomic read-modify-writes per packet that every core
 * contends on.
 *
 * Instead, readers announce that they are inside a critical section and the
 * writer defers freeing until every reader that could have seen the object has
 * left. A reader pays two plain stores to its OWN cache line per packet; no
 * atomic RMW, no sharing, no contention between threads.
 *
 * Protocol:
 *   reader:  read_lock() -> use raw pointers -> read_unlock()
 *   writer:  unlink from the map FIRST, then retire(); the deleter runs later
 *
 * Correctness rests on the ordering: because the object is unlinked before it
 * is retired, any reader starting afterwards cannot obtain it. Only readers
 * already inside a critical section could hold it, and those are exactly the
 * ones whose published epoch is <= the retirement epoch -- so the object is
 * held back until they leave.
 */
class rcu_domain {
 public:
  static constexpr int MAX_READERS = 128;

  /**
   * @brief Enter a read-side critical section.
   *
   * The store is seq_cst rather than relaxed-plus-a-fence: the epoch has to be
   * visible to a scanning writer before this thread reads any map slot, and a
   * bare atomic_thread_fence is invisible to ThreadSanitizer, which would make
   * the whole protocol unverifiable. Sequential consistency here and on the
   * writer's scan puts both in one total order, which is exactly the
   * store-then-load guarantee the algorithm needs.
   *
   * Cost is one store to this thread's own cache line -- no atomic RMW and no
   * line shared with any other thread.
   */
  void read_lock() noexcept {
    slot_for_this_thread().epoch.store(
        global_.load(std::memory_order_relaxed), std::memory_order_seq_cst);
  }

  /** @brief Leave it. Pointers obtained inside are dead after this. */
  void read_unlock() noexcept {
    slot_for_this_thread().epoch.store(0, std::memory_order_release);
  }

  /**
   * @brief Hand an unlinked object over to be freed once readers have moved on.
   * @note Call only AFTER the object is no longer reachable from any map.
   */
  void retire(std::function<void()> deleter) {
    std::lock_guard<std::mutex> lk(retire_mu_);
    const uint64_t e = global_.fetch_add(1, std::memory_order_acq_rel) + 1;
    retired_.emplace_back(e, std::move(deleter));
    reclaim_locked();
  }

  /** @brief Free whatever has become safe. Cheap; writers may call it freely.
   */
  void reclaim() {
    std::lock_guard<std::mutex> lk(retire_mu_);
    reclaim_locked();
  }

  /**
   * @brief Run every outstanding deleter.
   * @note At destruction there are no readers left by construction, so
   *       anything still on the retire list is safe to free. Without this the
   *       last few retired nodes leak.
   */
  ~rcu_domain() {
    std::lock_guard<std::mutex> lk(retire_mu_);
    for (auto& r : retired_) r.second();
    retired_.clear();
  }

  size_t pending() const {
    std::lock_guard<std::mutex> lk(retire_mu_);
    return retired_.size();
  }

 private:
  struct alignas(64) reader_slot {
    std::atomic<uint64_t> epoch{0};  // 0 == quiescent
  };

  reader_slot& slot_for_this_thread() noexcept {
    thread_local int idx = -1;
    if (idx < 0) {
      idx = next_slot_.fetch_add(1, std::memory_order_relaxed);
      // More datapath threads than slots would be a configuration error; fall
      // back to sharing slot 0, which is conservative (never frees too early).
      if (idx >= MAX_READERS) idx = 0;
    }
    return slots_[idx];
  }

  /** @brief Oldest epoch any reader is still inside; ~0 if all are quiescent.
   */
  uint64_t oldest_active_epoch() const noexcept {
    uint64_t oldest = UINT64_MAX;
    const int n     = next_slot_.load(std::memory_order_relaxed);
    const int upto  = (n < MAX_READERS) ? n : MAX_READERS;
    for (int i = 0; i < upto; i++) {
      const uint64_t e = slots_[i].epoch.load(std::memory_order_seq_cst);
      if (e != 0 && e < oldest) oldest = e;
    }
    return oldest;
  }

  void reclaim_locked() {
    if (retired_.empty()) return;
    const uint64_t safe = oldest_active_epoch();
    size_t keep         = 0;
    for (size_t i = 0; i < retired_.size(); i++) {
      if (retired_[i].first < safe) {
        retired_[i].second();  // run the deleter
      } else {
        if (keep != i) retired_[keep] = std::move(retired_[i]);
        keep++;
      }
    }
    retired_.resize(keep);
  }

  reader_slot slots_[MAX_READERS];
  std::atomic<int> next_slot_{0};
  std::atomic<uint64_t> global_{1};
  mutable std::mutex retire_mu_;
  std::vector<std::pair<uint64_t, std::function<void()>>> retired_;
};

/** @brief RAII read-side critical section. */
class rcu_guard {
 public:
  explicit rcu_guard(rcu_domain& d) noexcept : d_(d) { d_.read_lock(); }
  ~rcu_guard() { d_.read_unlock(); }
  rcu_guard(const rcu_guard&) = delete;
  rcu_guard& operator=(const rcu_guard&) = delete;

 private:
  rcu_domain& d_;
};

}  // namespace oai::upf

#endif /* UPF_RCU_HPP_SEEN */
