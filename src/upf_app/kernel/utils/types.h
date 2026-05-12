/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef BPF_TYPES_H
#define BPF_TYPES_H

enum ret_code {
  FAILURE = -1,  // Distinguished frop drop for further processing later on. We
                 // may not drop the packet
  SUCCESS  = 0,
  PASS     = 1,
  DROP     = 2,
  REDIRECT = 3,
};

#endif  // BPF_TYPES_H