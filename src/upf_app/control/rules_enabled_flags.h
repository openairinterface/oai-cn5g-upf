/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __RULES_ENABLED_FLAGS_H__
#define __RULES_ENABLED_FLAGS_H__

// clang-format off
 
 /** @brief QER — QoS Enforcement Rule (gate + MBR/GBR rate shaping).
  *
  *  Relevant IEs (3GPP TS 29.244 V17.10.0):
  *    §8.2.75  QER ID         (Mandatory in Create QER — Table 7.5.2.5-1)
  *    §8.2.7   Gate Status    (Mandatory — UL/DL open or closed)
  *    §8.2.8   MBR            (Conditional — Maximum Bit Rate)
  *    §8.2.9   GBR            (Conditional — Guaranteed Bit Rate)
  *    §8.2.89  QFI            (Conditional — QoS Flow Identifier)
  *    §8.2.88  RQI            (Optional  — Reflective QoS Indication)
  */
 #define RULE_QER_ENABLED (1U << 0)
 
 /** @brief URR — Usage Reporting Rule (volume/time measurement).
  *
  *  Relevant IEs (3GPP TS 29.244 V17.10.0):
  *    §8.2.54  URR ID              (Mandatory — Table 7.5.2.4-1)
  *    TODO     Measurement Method  (Mandatory — VOLUM/DURAT/EVENT; §-ref TBD)
  *    TODO     Reporting Triggers  (Mandatory; §-ref TBD)
  *    TODO     Volume Threshold    (Conditional; §-ref TBD)
  *    TODO     Time Threshold      (Conditional; §-ref TBD)
  *    TODO     Monitoring Time     (Optional; §-ref TBD)
  *
  *  @note §-refs for URR sub-IEs beyond URR ID are not in our verified
  *        V17.10.0 §-ref map yet and will be filled in when the URR IE
  *        table is audited in a dedicated pass.
  */
 #define RULE_URR_ENABLED (1U << 1)
 
 /** @brief BAR — Buffering Action Rule (DL data notification for idle UEs).
  *
  *  Relevant IEs (3GPP TS 29.244 V17.10.0):
  *    §8.2.57  BAR ID                          (Mandatory — Table 7.5.2.6-1)
  *    §8.2.28  Downlink Data Notification Delay (Optional — N4 only)
  *    §8.2.100 Suggested Buffering Packets Count (Optional — Sxb/Sxc/N4)
  */
 #define RULE_BAR_ENABLED (1U << 2)
 
 /** @brief MAR — Multi-Access Rule (ATSSS access steering).
  *
  *  Relevant IEs (3GPP TS 29.244 V17.10.0):
  *    §8.2.123 MAR ID                  (Mandatory — Table 7.5.2.8-1)
  *    §8.2.126 Weight (AFAI)           (Conditional — per access steering)
  *    §8.2.127 Priority (AFAI)         (Conditional)
  *    §8.2.197 Steering Mode Indicator (Optional — TODO: not yet in OAI lib)
  */
 #define RULE_MAR_ENABLED (1U << 3)

// clang-format on

#endif /* __RULES_ENABLED_FLAGS_H__ */
