#ifndef __MAC_PDU_SESSION_H__
#define __MAC_PDU_SESSION_H__

#include <ie/teid.h>
#include <types.h>
#include <linux/if_ether.h>

struct mac_pdu_session_value {
  teid_t_ teid;
  u32 ipv4_address;
};

struct eth__session_id {
  teid_t_ teid_ul;   // TEID for uplink
  teid_t_ teid_dl;   // TEID for downlink
  u32 ipv4_address;  // To support multiple N3 interfaces
  u64 seid;          // Session ID
};

#endif  // __MAC_PDU_SESSION_H__
