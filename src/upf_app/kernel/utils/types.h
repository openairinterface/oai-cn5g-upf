#ifndef BPF_TYPES_H
#define BPF_TYPES_H

/**
 * @brief Return codes for internal functions
 *
 * These codes provide fine-grained control over packet processing decisions.
 * They are converted to XDP actions at the entry point functions.
 */
typedef enum {
  RET_FAILURE  = -1, /**< Operation failed, packet may be recoverable */
  RET_SUCCESS  = 0,  /**< Operation completed successfully */
  RET_PASS     = 1,  /**< Pass packet to kernel stack or TC */
  RET_DROP     = 2,  /**< Drop packet immediately */
  RET_REDIRECT = 3,  /**< Redirect packet to another interface */
} return_code;

/**
 * @brief Traffic direction constants
 */
#define DIR_UPLINK 0   /**< N3 to N6 direction (RAN to Data Network) */
#define DIR_DOWNLINK 1 /**< N6 to N3 direction (Data Network to RAN) */

#endif  // BPF_TYPES_H