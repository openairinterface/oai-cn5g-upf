#ifndef __MAC_PDU_SESSION_H__
#define __MAC_PDU_SESSION_H__

#include <ie/teid.h>
#include <types.h>
#include <linux/if_ether.h>

struct mac_pdu_session_value {
  teid_t_ teid;
  u32 ipv4_address;
};

#endif  // __MAC_PDU_SESSION_H__
