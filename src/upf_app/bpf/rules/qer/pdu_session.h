
#ifndef __PDU_SESSION_H__
#define __PDU_SESSION_H__

#include <types.h>

struct pduSessionIds{
  uint64_t seid;
  uint64_t teidUl;
  uint64_t teidDl;
};

#endif //__PDU_SESSION_H__