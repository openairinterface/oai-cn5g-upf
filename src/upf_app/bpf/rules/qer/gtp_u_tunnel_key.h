#ifndef __GTP_U_TUNNEL_KEY_H__
#define __GTP_U_TUNNEL_KEY_H__

#include <types.h>

struct gtp_u_tunnel {
  u32 teid_ul;
  u32 teid_dl;
};

#endif  // __GTP_U_TUNNEL_KEY_H__
