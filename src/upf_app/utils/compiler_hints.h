/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef COMPILER_HINTS_H
#define COMPILER_HINTS_H

/**
 * @file compiler_hints.h
 * @brief Compiler optimization hints for branch prediction
 */

/**
 * @brief Hint to compiler that condition is likely true
 * Helps optimize branch prediction for hot paths
 */
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

/**
 * @brief Hint to compiler that condition is unlikely true
 * Helps optimize branch prediction for error paths
 */
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#endif  // COMPILER_HINTS_H
