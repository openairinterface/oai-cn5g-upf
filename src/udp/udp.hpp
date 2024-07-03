/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file udp.hpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/
#ifndef FILE_UDP_HPP_SEEN
#define FILE_UDP_HPP_SEEN

#include "conversions.hpp"
#include "endpoint.hpp"
#include "itti.hpp"
#include "thread_sched.hpp"

#include <folly/MPMCQueue.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/socket.h>

#include <iostream>
#include <map>
#include <memory>
#include <stdint.h>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>
#include <pthread.h>

class udp_application {
 public:
  virtual void handle_receive(
      char* recv_buffer, const std::size_t bytes_transferred,
      const endpoint& r_endpoint);
  virtual void start_receive(
      udp_application* gtp_stack,
      const util::thread_sched_params& sched_params);
};
class udp_server;

typedef struct udp_packet_q_item_s {
  char* buffer;
  endpoint r_endpoint;
  size_t size;
} udp_packet_q_item_t;

class udp_server {
#define UDP_RECV_BUFFER_SIZE 8192
 public:
  udp_server(const struct in_addr& address, const uint16_t port_num)
      : app_(nullptr),
        port_(port_num),
        num_threads_(1),
        free_pool_(nullptr),
        work_pool_(nullptr) {
    socket_ = create_socket(address, port_);
    if (socket_ > 0) {
      Logger::udp().debug(
          "udp_server::udp_server(%s:%d)",
          oai::utils::conv::toString(address).c_str(), port_);
      sa_family = AF_INET;
    } else {
      Logger::udp().error(
          "udp_server::udp_server(%s:%d)",
          oai::utils::conv::toString(address).c_str(), port_);
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      throw std::system_error(
          socket_, std::generic_category(), "GTPV1-U socket creation failed!");
    }
  }

  udp_server(const struct in6_addr& address, const uint16_t port_num)
      : app_(nullptr),
        port_(port_num),
        free_pool_(nullptr),
        work_pool_(nullptr) {
    socket_      = create_socket(address, port_);
    terminateRL_ = false;
    terminateWL_ = false;
    if (socket_ > 0) {
      Logger::udp().debug(
          "udp_server::udp_server(%s:%d)",
          oai::utils::conv::toString(address).c_str(), port_);
      sa_family = AF_INET6;
    } else {
      Logger::udp().error(
          "udp_server::udp_server(%s:%d)",
          oai::utils::conv::toString(address).c_str(), port_);
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      throw std::system_error(
          socket_, std::generic_category(), "GTPV1-U socket creation failed!");
    }
  }

  udp_server(const char* address, const uint16_t port_num)
      : app_(nullptr),
        port_(port_num),
        free_pool_(nullptr),
        work_pool_(nullptr) {
    socket_      = create_socket(address, port_);
    terminateRL_ = false;
    terminateWL_ = false;
    if (socket_ > 0) {
      Logger::udp().debug("udp_server::udp_server(%s:%d)", address, port_);
    } else {
      Logger::udp().error("udp_server::udp_server(%s:%d)", address, port_);
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      throw std::system_error(
          socket_, std::generic_category(), "GTPV1-U socket creation failed!");
    }
  }

  ~udp_server() {
    int res;

    Logger::udp().info("Starting the udp_server destruction");
    stop();

    // closing a socket is not enough for a blocking API call to stop.
    // shutdown is required. recvfrom will stop automically
    // and bytes_received should be equal to 0.
    shutdown(socket_, SHUT_RDWR);
    // waiting for the read thread to end
    while (terminateRL_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // now we can close the socket
    res = close(socket_);
    if (res != 0) {
      Logger::udp().error("close on socket_ failed %s", strerror(errno));
    }

    // Joining on all threads for completion
    rthread_.join();
    wthread_.join();

    // TODO delete/release elements in  the pool
    if (free_pool_) delete free_pool_;
    if (work_pool_) delete work_pool_;
    if (recv_buffer_alloc_) free(recv_buffer_alloc_);
    // free(udp_packet_q_item_alloc_);
    Logger::udp().info("Finished the udp_server destruction");
  }

  void udp_read_loop(const util::thread_sched_params& thread_sched_params);
  void udp_worker_loop(
      const int id, const util::thread_sched_params& sched_params);

  void async_send_to(
      const char* send_buffer, const ssize_t num_bytes,
      const endpoint& r_endpoint) {
    ssize_t bytes_written = sendto(
        socket_, send_buffer, num_bytes, 0,
        (struct sockaddr*) &r_endpoint.addr_storage,
        r_endpoint.addr_storage_len);
    if (bytes_written != num_bytes) {
      Logger::udp().error("sendto failed(%d:%s)\n", errno, strerror(errno));
    }
  }

  void async_send_to(
      const char* send_buffer, const ssize_t num_bytes,
      const struct sockaddr_in& r_endpoint) {
    ssize_t bytes_written = sendto(
        socket_, send_buffer, num_bytes, 0, (struct sockaddr*) &r_endpoint,
        sizeof(struct sockaddr_in));
    if (bytes_written != num_bytes) {
      Logger::udp().error("sendto failed(%d:%s)\n", errno, strerror(errno));
    }
  }

  void async_send_to(
      const char* send_buffer, const ssize_t num_bytes,
      const struct sockaddr_in6& r_endpoint) {
    ssize_t bytes_written = sendto(
        socket_, send_buffer, num_bytes, 0, (struct sockaddr*) &r_endpoint,
        sizeof(struct sockaddr_in6));
    if (bytes_written != num_bytes) {
      Logger::udp().error("sendto failed(%d:%s)\n", errno, strerror(errno));
    }
  }

  void start_receive(
      udp_application* gtp_stack,
      const util::thread_sched_params& sched_params);
  void stop(void);

 protected:
  int create_socket(const struct in_addr& address, const uint16_t port);
  int create_socket(const struct in6_addr& address, const uint16_t port);
  int create_socket(const char* address, const uint16_t port_num);

  // void handle_receive(const int& error, std::size_t bytes_transferred);

  static void handle_send(
      const char*, /*buffer*/
      const int& /*error*/, std::size_t /*bytes_transferred*/) {}

  // Should be in non swapable memory
  folly::MPMCQueue<udp_packet_q_item_t*>* free_pool_;
  folly::MPMCQueue<udp_packet_q_item_t*>* work_pool_;
  uint32_t num_threads_;
  char* recv_buffer_alloc_;
  // udp_packet_q_item_t *udp_packet_q_item_alloc_;
  udp_application* app_;
  std::thread rthread_;
  std::thread wthread_;
  bool terminateRL_;
  bool terminateWL_;
  int socket_;
  uint16_t port_;
  sa_family_t sa_family;
  pthread_t tmp_thread;
};

#endif /* FILE_UDP_HPP_SEEN */
