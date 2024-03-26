/**
 * N6 will listen to raw packets. This is because it can receive different types of packets i.e.,
 * NSH, VLAN, and just IP packets. We should create an N6 server that listens to any type of packets
 * and then handle the packets accordingly. There should be a send function for each type, e.g., send_nsh
 * There is more than one n6 interface. The implementation should allow creating multiple n6 sockets
 * and allow them to be referenced by name (e.g., internet.oai.org).
 * 
 * This will extend the raw socket server application which will allow it to bind to raw sockets.
*/

#ifndef FILE_N6_HPP_SEEN
#define FILE_N6_HPP_SEEN

#include "endpoint.hpp"
#include "raw.hpp"

#include <thread>

namespace oai {
namespace upf {
namespace app {

#define TASK_UPF_N4_TRIGGER_HEARTBEAT_REQUEST (0)
#define TASK_UPF_N4_TIMEOUT_HEARTBEAT_REQUEST (1)
#define TASK_UPF_N4_TIMEOUT_ASSOCIATION_REQUEST (2)

class upf_n6 : public raw_application {
 private:
  std::thread::id thread_id;
  std::thread thread;

  raw_server raw_s;

 protected:
  uint32_t id;
  
 public:
  upf_n6();
  upf_n6(upf_n6 const&) = delete;
  void operator=(upf_n6 const&) = delete;

  virtual void handle_receive(
      const char* recv_buffer, const std::size_t bytes_transferred);


};
}  // namespace app
}  // namespace upf
}  // namespace oai
#endif /* FILE_N6_HPP_SEEN */