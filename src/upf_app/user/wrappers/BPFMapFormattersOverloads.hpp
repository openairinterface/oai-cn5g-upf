#pragma once

#include "BPFMapFormatters.hpp"
#include <session_id.h>
#include <arp_table.h>
#include <rules_matching_pdr.h>

namespace upf::utils {

//==============================================================================
// Overloads for BPF Structure Types
//==============================================================================

// session_id
template<>
inline std::string FormatBPFValue<struct session_id>(
    const struct session_id& value) {
  return FormatSessionId(value);
}

// arp_entry
template<>
inline std::string FormatBPFValue<struct arp_entry>(
    const struct arp_entry& value) {
  return FormatArpEntry(value);
}

// pdrs_per_session (key for rules_match_pdr map)
template<>
inline std::string FormatBPFValue<struct pdrs_per_session>(
    const struct pdrs_per_session& value) {
  return FormatPdrKey(value);
}

// rules_match_pdr (FAR + QER)
template<>
inline std::string FormatBPFValue<struct rules_match_pdr>(
    const struct rules_match_pdr& value) {
  std::ostringstream oss;
  oss << "{FAR_ID=" << value.far.far_id.far_id
      << ", QER_ID=" << value.qer.qer_id.qer_id << ", Action="
      << (value.far.apply_action.forw ? "FORW" :
          value.far.apply_action.drop ? "DROP" :
                                        "BUFF")
      << "}";
  return oss.str();
}

// Add more as needed...

}  // namespace upf::utils