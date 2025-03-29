#ifndef __QOS_FLOW_IDENTIFIER_H__
#define __QOS_FLOW_IDENTIFIER_H__

#include <types.h>
#include <ie/ie_base.h>

// 8.2.89 QFI
typedef struct qfi_s {
  u8 spare : 2;
  u8 qfi : 6;
  // qfi_s() : qfi(0), spare(0) {}
  // qfi_s(const u8& q) : qfi(q), spare(0) {}
  // qfi_s(const struct qfi_s& q) : qfi(q.qfi), spare(q.spare) {}
  // inline bool operator==(const struct qfi_s& rhs) const {
  //   return ((qfi == rhs.qfi) && (spare == rhs.spare));
  // }
  // inline bool operator!=(const struct qfi_s& rhs) const {
  //   return !((qfi == rhs.qfi) && (spare == rhs.spare));
  // }
} qfi_t;

#endif  // __QOS_FLOW_IDENTIFIER_H__