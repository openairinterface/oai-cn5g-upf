// BPFMapFormatters.hpp - FIXED VERSION
// Fixes: Missing includes for struct definitions

#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <type_traits>
#include <cstring>

// These headers define the BPF structures we need to format
extern "C" {
#include "session_id.h"          // For struct session_id
#include "arp_table.h"           // For struct arp_entry
#include "rules_matching_pdr.h"  // For struct pdrs_per_session, rules_match_pdr
// Add any other struct headers you need
}

namespace upf::utils {

//==============================================================================
// Helper Functions
//==============================================================================

inline std::string FormatIPv4(uint32_t ip) {
  struct in_addr addr;
  addr.s_addr = ip;
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
    return std::string(buf);
  }
  return "INVALID_IP";
}

inline std::string FormatMAC(const uint8_t* mac) {
  char buf[18];
  snprintf(
      buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
      mac[3], mac[4], mac[5]);
  return std::string(buf);
}

//==============================================================================
// Generic Formatter (fallback for unknown types)
//==============================================================================

template<typename T>
std::string FormatBPFValue(const T& value, const std::string& context = "") {
  std::ostringstream oss;

  // Simple integers
  if constexpr (std::is_integral_v<T> && sizeof(T) <= 8) {
    if constexpr (std::is_unsigned_v<T>) {
      oss << value;
    } else {
      oss << value;
    }
  }
  // Anything else: hex dump
  else {
    oss << "0x";
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
    for (size_t i = 0; i < sizeof(T) && i < 32; ++i) {  // Max 32 bytes
      oss << std::hex << std::setw(2) << std::setfill('0')
          << static_cast<int>(bytes[i]);
    }
    if (sizeof(T) > 32) {
      oss << "...";
    }
  }

  return oss.str();
}

//==============================================================================
// Specializations for Primitive Types
//==============================================================================

template<>
inline std::string FormatBPFValue<uint8_t>(
    const uint8_t& value, const std::string& context) {
  return std::to_string(static_cast<int>(value));
}

template<>
inline std::string FormatBPFValue<uint16_t>(
    const uint16_t& value, const std::string& context) {
  return std::to_string(value);
}

template<>
inline std::string FormatBPFValue<uint32_t>(
    const uint32_t& value, const std::string& context) {
  // Check if context suggests this is an IP address
  if (context.find("ip") != std::string::npos ||
      context.find("addr") != std::string::npos ||
      context.find("ue") != std::string::npos) {
    return FormatIPv4(value);
  }
  return std::to_string(value);
}

template<>
inline std::string FormatBPFValue<uint64_t>(
    const uint64_t& value, const std::string& context) {
  // Check if context suggests this is a SEID
  if (context.find("seid") != std::string::npos) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
  }
  return std::to_string(value);
}

//==============================================================================
// Helper Functions for Struct Formatting
//==============================================================================

inline std::string FormatSessionId(const struct session_id& sid) {
  std::ostringstream oss;
  oss << "{TEID_UL=" << ntohl(sid.teid_ul) << ", TEID_DL=" << ntohl(sid.teid_dl)
      << ", SEID=0x" << std::hex << sid.seid << std::dec << "}";
  return oss.str();
}

inline std::string FormatArpEntry(const struct arp_entry& entry) {
  std::ostringstream oss;
  oss << "{IP=" << FormatIPv4(entry.ipv4_address)
      << ", MAC=" << FormatMAC(entry.mac_address) << "}";
  return oss.str();
}

inline std::string FormatPdrKey(const struct pdrs_per_session& key) {
  std::ostringstream oss;
  oss << "{PDR=" << key.pdr_id << ", SEID=0x" << std::hex << key.seid
      << std::dec << "}";
  return oss.str();
}

//==============================================================================
// Specializations for BPF Structures
//==============================================================================

// session_id structure
template<>
inline std::string FormatBPFValue<struct session_id>(
    const struct session_id& value, const std::string& context) {
  return FormatSessionId(value);
}

// arp_entry structure
template<>
inline std::string FormatBPFValue<struct arp_entry>(
    const struct arp_entry& value, const std::string& context) {
  return FormatArpEntry(value);
}

// pdrs_per_session structure (map key)
template<>
inline std::string FormatBPFValue<struct pdrs_per_session>(
    const struct pdrs_per_session& value, const std::string& context) {
  return FormatPdrKey(value);
}

// rules_match_pdr structure (map value)
template<>
inline std::string FormatBPFValue<struct rules_match_pdr>(
    const struct rules_match_pdr& value, const std::string& context) {
  std::ostringstream oss;
  oss << "{FAR=" << value.far.far_id.far_id;

  // Show action
  if (value.far.apply_action.forw) {
    oss << " (FORW";
    if (value.far.forwarding_parameters.outer_header_creation.teid) {
      oss << " TEID="
          << ntohl(value.far.forwarding_parameters.outer_header_creation.teid);
    }
    oss << ")";
  } else if (value.far.apply_action.drop) {
    oss << " (DROP)";
  } else if (value.far.apply_action.buff) {
    oss << " (BUFF)";
  }

  // Show QER if present
  if (value.qer.qer_id.qer_id > 0) {
    oss << ", QER=" << value.qer.qer_id.qer_id;
  }

  oss << "}";
  return oss.str();
}

}  // namespace upf::utils