
#ifndef __PDU_SESSION_H__
#define __PDU_SESSION_H__

#include <types.h>

struct  pdu_session_ids{
  uint64_t seid;
  uint32_t teid_ul;
  uint32_t teid_dl;
};

#endif //__PDU_SESSION_H__