/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "itti_msg.hpp"
#include "itti.hpp"

extern itti_mw* itti_inst;

// Initialiser order follows the declaration order in itti_msg.hpp
// (msg_num, origin, destination, msg_type).
itti_msg::itti_msg()
    : origin(TASK_NONE), destination(TASK_NONE), msg_type(ITTI_MSG_TYPE_NONE) {
  msg_num = itti_inst->increment_message_number();
};

itti_msg::itti_msg(
    const itti_msg_type_t msg_type, task_id_t origin, task_id_t destination)
    : origin(origin), destination(destination), msg_type(msg_type) {
  msg_num = itti_inst->increment_message_number();
};

itti_msg::itti_msg(const itti_msg& i)
    : msg_num(i.msg_num),
      origin(i.origin),
      destination(i.destination),
      msg_type(i.msg_type){};

const char* itti_msg::get_msg_name() {
  return "UNINITIALIZED";
}
