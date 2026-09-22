/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef UPF_RCU_HPP_SEEN
#define UPF_RCU_HPP_SEEN

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

  /**
   * @brief This thread's slot in this domain.
   *
   * The index is per thread and process-wide rather than per domain, and every
   * domain indexes its own array of slots with it. A per-domain counter cannot
   * work: the cached index lives in one thread_local shared by all domains, so
   * a second domain -- one built per case in a test, or a switch torn down and
   * rebuilt -- would find an index its own counter never issued and sit in a
   * slot nothing scans.
   */
  reader_slot& slot_for_this_thread() noexcept {
    thread_local slot_ticket ticket;
    return slots_[ticket.idx];
  }

  /** @brief A thread's slot number, held for as long as the thread lives.
   *
   *  Returning it on exit is what keeps MAX_READERS a limit on readers alive at
   *  once rather than on threads ever created: the datapath makes its threads
   *  once, but a test that runs a case per thread would otherwise walk into the
   *  abort below after enough cases.
   */
  struct slot_ticket {
    const int idx;
    slot_ticket() noexcept : idx(claim_thread_slot()) {}
    ~slot_ticket() { release_thread_slot(idx); }
  };

  static int claim_thread_slot() noexcept {
    std::lock_guard<std::mutex> lk(slot_mu_);
    if (!free_slots_.empty()) {
      const int idx = free_slots_.back();
      free_slots_.pop_back();
      return idx;  // quiescent in every domain: its thread left before it
    }
    const int idx = high_water_.load(std::memory_order_relaxed);
    // Two threads on one slot is a use-after-free waiting to happen: the
    // first to read_unlock() zeroes the epoch the other is still inside, so
    // the reclaimer frees memory that thread is reading. There is no safe
    // fallback, and the config caps keep this unreachable, so stop here
    // rather than degrade into something that corrupts memory silently.
    if (idx >= MAX_READERS) {
      fprintf(
          stderr,
          "rcu_domain: more than %d reader threads at once (check the "
          "datapath thread/queue counts)\n",
          MAX_READERS);
      std::abort();
    }
    high_water_.store(idx + 1, std::memory_order_relaxed);
    return idx;
  }

  static void release_thread_slot(int idx) noexcept {
    std::lock_guard<std::mutex> lk(slot_mu_);
    free_slots_.push_back(idx);
  }

  /** @brief Oldest epoch any reader is still inside; ~0 if all are quiescent.
   */
  uint64_t oldest_active_epoch() const noexcept {
    uint64_t oldest = UINT64_MAX;
    // Threads that never read this domain leave their slot at 0, so scanning
    // every slot handed out process-wide costs a few quiescent loads.
    const int n    = high_water_.load(std::memory_order_relaxed);
    const int upto = (n < MAX_READERS) ? n : MAX_READERS;
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
  /// Slot bookkeeping for the whole process: a thread keeps one number in
  /// every domain it reads, so the assignment cannot be per domain.
  /// high_water_ is how far any reclaimer has to scan and only ever grows;
  /// free_slots_ holds the numbers of threads that have exited.
  static inline std::atomic<int> high_water_{0};
  static inline std::mutex slot_mu_;
  static inline std::vector<int> free_slots_;
  std::atomic<uint64_t> global_{1};
  mutable std::mutex retire_mu_;
  std::vector<std::pair<uint64_t, std::function<void()>>> retired_;
};

/** @brief RAII read-side critical section. */
class rcu_guard {
 public:
  explicit rcu_guard(rcu_domain& d) noexcept : d_(d) { d_.read_lock(); }
  ~rcu_guard() { d_.read_unlock(); }
  rcu_guard(const rcu_guard&)            = delete;
  rcu_guard& operator=(const rcu_guard&) = delete;

 private:
  rcu_domain& d_;
};

}  // namespace oai::upf

#endif /* UPF_RCU_HPP_SEEN */
