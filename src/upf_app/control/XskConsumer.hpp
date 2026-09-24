/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef XSK_CONSUMER_HPP_
#define XSK_CONSUMER_HPP_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

class BPFMap;

namespace oai {
namespace upf {
namespace app {

/**
 * @class XskConsumer
 * @brief Receives the DL packets the XDP BAR program holds, over AF_XDP, and
 *        puts them in the DL buffer (paging on the eBPF datapath).
 *
 * The BAR (Buffering Action Rule) program redirects each buffered packet to
 * xskmap[rx_queue_index]. This class opens one AF_XDP socket and one UMEM
 * (packet memory shared with the kernel) per N6 RX queue. One thread polls
 * them and copies each packet into the DL buffer.
 *
 * libxdp never loads an XDP program here (INHIBIT_PROG_LOAD); the UPF uses
 * its own program and xskmap. Start() sets up every queue or none. Stop() is
 * idempotent and never throws, because it runs in the signal handler.
 */
class XskConsumer {
 public:
  /// What Start() needs; the caller reads it from the configuration.
  struct Config {
    std::string ifname;             ///< N6 interface
    uint32_t frame_size       = 0;  ///< bytes per UMEM frame (2048 or 4096)
    uint32_t frames_per_queue = 0;  ///< frames and ring slots per queue (2^n)
    uint64_t umem_max_bytes   = 0;  ///< cap on all UMEMs together
    uint32_t max_queues       = 0;  ///< xskmap slots
    bool skb_mode             = false;  ///< XDP attached in SKB (generic) mode
  };

  /** @brief Snapshot of the consumer counters. */
  struct Counters {
    uint64_t received;       ///< frames taken off the RX rings
    uint64_t malformed;      ///< dropped: not Ethernet + valid IPv4
    uint64_t not_buffering;  ///< dropped: no PDR matches, or FAR not BUFF
    uint64_t stored;         ///< held by the DL buffer
    uint64_t refused;        ///< refused by the DL buffer (bounds, stale uid)
  };

  /** @brief poll() timeout; bounds shutdown latency without spinning. */
  static constexpr int kPollTimeoutMs = 200;
  /** @brief Descriptors taken off one RX ring per pass. */
  static constexpr uint32_t kRxBatch = 64;

  XskConsumer();
  ~XskConsumer();

  XskConsumer(const XskConsumer&)            = delete;
  XskConsumer& operator=(const XskConsumer&) = delete;

  /**
   * @brief Open one AF_XDP socket per N6 RX queue, publish them in @p xskmap
   *        and start the poll thread.
   *
   * Checks first that the queue count (/sys/class/net/<if>/queues/rx-*) fits
   * in the map and that queues x frames x frame size fits the UMEM cap.
   * @return true if the poll thread is running. On false nothing is left
   *         behind (no socket, no UMEM, no map entry) and one error is logged.
   */
  bool Start(const Config& cfg, const std::shared_ptr<BPFMap>& xskmap);

  /** @brief Stop and join the poll thread, then remove the map entries and
   *  delete the sockets and UMEMs. Idempotent; never throws. */
  void Stop() noexcept;

  /** @brief True while the poll thread is alive. */
  bool IsRunning() const;

  /** @brief Current counter values. */
  Counters GetCounters() const;

  /** @brief Number of RX queues of @p ifname from sysfs; -1 if unreadable. */
  static int CountRxQueues(const std::string& ifname);

 private:
  struct Queue;

  /** @brief Delete every socket, UMEM and map entry. Not thread-safe: only
   *  called with no poll thread running. */
  void ReleaseAll() noexcept;

  /** @brief Remove every published xskmap entry. Idempotent. Called by the
   *  poll thread on a fatal error, or with no poll thread running. */
  void Unpublish() noexcept;

  /** @brief Poll thread body. */
  void PollLoop();

  /** @brief Take what one RX ring holds and give the frames back. */
  void DrainQueue(Queue& q);

  /** @brief One frame: parse, classify, enqueue (copy). */
  void HandleFrame(const uint8_t* frame, uint32_t len);

  std::vector<std::unique_ptr<Queue>> queues_;
  std::shared_ptr<BPFMap> xskmap_;
  uint32_t frame_size_ = 0;
  std::thread poll_thread_;
  std::atomic<bool> running_{false};

  std::atomic<uint64_t> received_{0};
  std::atomic<uint64_t> malformed_{0};
  std::atomic<uint64_t> not_buffering_{0};
  std::atomic<uint64_t> stored_{0};
  std::atomic<uint64_t> refused_{0};
};

}  // namespace app
}  // namespace upf
}  // namespace oai

#endif  // XSK_CONSUMER_HPP_
