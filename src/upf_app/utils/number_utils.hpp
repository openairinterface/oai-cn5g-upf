/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef NUMBER_UTILS_HPP
#define NUMBER_UTILS_HPP

#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <locale>

namespace oai::utils {

/**
 * @brief Format number with thousand separators
 *
 * @param value Number to format
 * @param style Separator style:
 *              "comma" or "us" = 10,000,000 (US/UK style)
 *              "period" or "eu" = 10.000.000 (European style)
 *              "space" or "intl" = 10 000 000 (International style)
 * @return Formatted string
 */
inline std::string FormatNumber(
    uint64_t value, const std::string& style = "comma") {
  std::string num_str = std::to_string(value);
  std::string result;
  int count = 0;

  char separator;
  if (style == "comma" || style == "us") {
    separator = ',';
  } else if (style == "period" || style == "eu") {
    separator = '.';
  } else if (style == "space" || style == "intl") {
    separator = ' ';
  } else {
    separator = ',';  // Default to comma
  }

  // Insert separator every 3 digits from right to left
  for (int i = num_str.length() - 1; i >= 0; i--) {
    if (count == 3) {
      result = separator + result;
      count  = 0;
    }
    result = num_str[i] + result;
    count++;
  }

  return result;
}

//==============================================================================
// ALTERNATIVE: Using std::locale (if available on your system)
//==============================================================================

// This uses system locale but might not work on all embedded systems
inline std::string FormatNumberLocale(uint64_t value) {
  std::stringstream ss;
  ss.imbue(std::locale("en_US.UTF-8"));  // or "de_DE.UTF-8" for European
  ss << std::fixed << value;
  return ss.str();
}

}  // namespace oai::utils

#endif  // NUMBER_UTILS_HPP
