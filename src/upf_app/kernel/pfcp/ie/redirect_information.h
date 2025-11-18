#ifndef __REDIRECT_INFORMATION_H__
#define __REDIRECT_INFORMATION_H__

#include "linux/custom_types.h"
#include "ie/ie_base.h"

//-------------------------------------
// 8.2.20 Redirect Information
typedef struct redirect_information {
  ie_base_t base;
  u8 redirect_address_type : 4;
  u8 spare : 4;
  u16 redirect_server_address_length;
} redirect_information_t;

#endif  // __REDIRECT_INFORMATION_H__