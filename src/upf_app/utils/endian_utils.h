/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef ENDIAN_UTILS_H
#define ENDIAN_UTILS_H

#include <cstdint>
#include <endian.h>

/**
 * @file endian_utils.h
 * @brief Byte order and endianness utility functions
 */

namespace upf {
namespace utils {

/**
 * @brief Check if system is little-endian at runtime
 * @return true if little-endian, false if big-endian
 * @note This is a runtime check. For compile-time, use __BYTE_ORDER__
 */
inline bool IsLittleEndian() {
  constexpr uint32_t value = 1;
  return (*reinterpret_cast<const uint8_t*>(&value) == 1);
}

/**
 * @brief Check if system is big-endian at runtime
 * @return true if big-endian, false if little-endian
 */
inline bool IsBigEndian() {
  return !IsLittleEndian();
}

/**
 * @brief Convert host byte order to network byte order (32-bit)
 * No-op on big-endian systems, byte swap on little-endian
 */
inline uint32_t HostToNetwork32(uint32_t value) {
  return htobe32(value);
}

/**
 * @brief Convert network byte order to host byte order (32-bit)
 * No-op on big-endian systems, byte swap on little-endian
 */
inline uint32_t NetworkToHost32(uint32_t value) {
  return be32toh(value);
}

}  // namespace utils
}  // namespace upf

// Legacy compatibility macros (if needed)
#ifndef is_little_endian
#define is_little_endian() upf::utils::IsLittleEndian()
#endif

#endif  // ENDIAN_UTILS_H
