#ifndef __SESSION_ID_H__
#define __SESSION_ID_H__

#include <types.h>
#include <stdint.h>

struct session_id {
  u32 teid_ul;
  u32 teid_dl;
  u32 seid;
};

#endif  // __SESSION_ID_H__