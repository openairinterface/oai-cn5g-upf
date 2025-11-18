#ifndef __APPLY_ACTION_H__
#define __APPLY_ACTION_H__

#include "linux/custom_types.h"

/* Apply Action flags - bit field order for little-endian
 * 3GPP TS 29.244 Release 16 - Section 8.2.26
 * Bit flags that can be combined */

typedef struct apply_action {
  u8 spare : 3; /* Bits 0-2: Reserved */
  u8 dupl : 1;  /* Bit 3: DUPLICATE */
  u8 nocp : 1;  /* Bit 4: NOTIFY CP */
  u8 buff : 1;  /* Bit 5: BUFFER */
  u8 forw : 1;  /* Bit 6: FORWARD */
  u8 drop : 1;  /* Bit 7: DROP */
} apply_action_t;

/* Apply Action bit masks */
#define APPLY_ACTION_DUPL 0x08 /* Bit 3: 0b00001000 */
#define APPLY_ACTION_NOCP 0x10 /* Bit 4: 0b00010000 */
#define APPLY_ACTION_BUFF 0x20 /* Bit 5: 0b00100000 */
#define APPLY_ACTION_FORW 0x40 /* Bit 6: 0b01000000 */
#define APPLY_ACTION_DROP 0x80 /* Bit 7: 0b10000000 */

#endif  // __APPLY_ACTION_H__