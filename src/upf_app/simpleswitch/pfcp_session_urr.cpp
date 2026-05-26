/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*! \file pfcp_session.cpp
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr
*/

#include "pfcp_session.hpp"
#include "pfcp_switch.hpp"
#include "logger.hpp"

using namespace pfcp;
using namespace oai::upf::app;

extern pfcp_switch* pfcp_switch_inst;

//------------------------------------------------------------------------------
bool pfcp_session::get(
    const uint32_t far_id, std::shared_ptr<pfcp::pfcp_far>& far) const {
  for (auto it : fars) {
    if (it->far_id.far_id == far_id) {
      far = it;
      return true;
    }
  }
  return false;
}
//------------------------------------------------------------------------------
bool pfcp_session::get(
    const uint16_t pdr_id, std::shared_ptr<pfcp::pfcp_pdr>& pdr) const {
  for (auto it : pdrs) {
    if (it->pdr_id.rule_id == pdr_id) {
      pdr = it;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::get(
    const uint32_t qer_id, std::shared_ptr<pfcp::pfcp_qer>& qer) const {
  for (auto it : qers) {
    if (it->qer_id.second.qer_id == qer_id) {
      qer = it;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::get(
    const uint32_t urr_id, std::shared_ptr<pfcp::pfcp_urr>& urr) const {
  for (auto it : urrs) {
    if (it->urr_id.urr_id == urr_id) {
      urr = it;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
void pfcp_session::add(std::shared_ptr<pfcp::pfcp_far> far) {
  Logger::upf_n4().info("pfcp_session::add(far) seid " SEID_FMT " ", seid);

  // Update (just TEID for now) the FAR if existed
  for (std::vector<std::shared_ptr<pfcp::pfcp_far>>::iterator it = fars.begin();
       it != fars.end(); ++it) {
    if ((*it)->far_id.far_id == far->far_id.far_id) {
      Logger::upf_n4().info(
          "pfcp_session::update(far) seid " SEID_FMT " ", seid);
      (*it)->forwarding_parameters.second.outer_header_creation.second.teid =
          far->forwarding_parameters.second.outer_header_creation.second.teid;
      return;
    }
  }

  // Otherwise, add to the list of FARs
  fars.push_back(far);
}

//------------------------------------------------------------------------------
void pfcp_session::add(std::shared_ptr<pfcp::pfcp_pdr> pdr) {
  Logger::upf_n4().info("pfcp_session::add(pdr) seid " SEID_FMT " ", seid);
  pdrs.push_back(pdr);
}

//------------------------------------------------------------------------------
void pfcp_session::add(std::shared_ptr<pfcp::pfcp_qer> qer) {
  Logger::upf_n4().info("pfcp_session::add(qer) seid " SEID_FMT " ", seid);
  qers.push_back(qer);
}

//------------------------------------------------------------------------------
void pfcp_session::add(std::shared_ptr<pfcp::pfcp_urr> urr) {
  Logger::upf_n4().info("pfcp_session::add(urr) seid " SEID_FMT " ", seid);
  urrs.push_back(urr);
}

//------------------------------------------------------------------------------
bool pfcp_session::remove(const pfcp::far_id_t& far_id, uint8_t& cause_value) {
  for (std::vector<std::shared_ptr<pfcp::pfcp_far>>::iterator it = fars.begin();
       it != fars.end(); ++it) {
    if ((*it)->far_id.far_id == far_id.far_id) {
      Logger::upf_n4().info(
          "pfcp_session::remove(far) seid " SEID_FMT " ", seid);
      fars.erase(it);
      return true;
    }
  }
  cause_value = pfcp::CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;  //??
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::remove(const pfcp::pdr_id_t& pdr_id, uint8_t& cause_value) {
  for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::iterator it = pdrs.begin();
       it != pdrs.end(); ++it) {
    if ((*it)->pdr_id.rule_id == pdr_id.rule_id) {
      Logger::upf_n4().info(
          "pfcp_session::remove(pdr) seid " SEID_FMT " ", seid);
      pdrs.erase(it);
      return true;
    }
  }
  cause_value = pfcp::CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;  //??
  return false;
}

//------------------------------------------------------------------------------
/**
 * Remove QER
 */
bool pfcp_session::remove(const pfcp::qer_id_t& qer_id, uint8_t& cause_value) {
  for (std::vector<std::shared_ptr<pfcp::pfcp_qer>>::iterator it = qers.begin();
       it != qers.end(); ++it) {
    if ((*it)->qer_id.second.qer_id == qer_id.qer_id) {
      Logger::upf_n4().info(
          "pfcp_session::remove(qer) seid " SEID_FMT " ", seid);
      qers.erase(it);
      return true;
    }
  }
  cause_value = pfcp::CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;  //??
  return false;
}

//------------------------------------------------------------------------------
/**
 * Remove URR
 */
bool pfcp_session::remove(const pfcp::urr_id_t& urr_id, uint8_t& cause_value) {
  for (std::vector<std::shared_ptr<pfcp::pfcp_urr>>::iterator it = urrs.begin();
       it != urrs.end(); ++it) {
    if ((*it)->urr_id.urr_id == urr_id.urr_id) {
      Logger::upf_n4().info(
          "pfcp_session::remove(urr) seid " SEID_FMT " ", seid);
      urrs.erase(it);
      return true;
    }
  }
  cause_value = pfcp::CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;  //??
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::update(
    const pfcp::update_far& update, uint8_t& cause_value) {
  std::shared_ptr<pfcp::pfcp_far> far = {};
  if (get(update.far_id.far_id, far)) {
    if (far->update(update, cause_value)) {
      return true;
    }
    return false;
  }
  cause_value = pfcp::CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  return false;
}

//------------------------------------------------------------------------------
/**
 * Update PDR
 */
bool pfcp_session::update(
    const pfcp::update_pdr& update, uint8_t& cause_value) {
  std::shared_ptr<pfcp::pfcp_pdr> pdr = {};
  if (get(update.pdr_id.rule_id, pdr)) {
    if (pdr->update(update, cause_value)) {
      return true;
    }
    return false;
  }
  cause_value = pfcp::CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  return false;
}

//------------------------------------------------------------------------------
/**
 * Update QER
 */
bool pfcp_session::update(
    const pfcp::update_qer& update, uint8_t& cause_value) {
  std::shared_ptr<pfcp::pfcp_qer> qer = {};
  if (get(update.qer_id.second.qer_id, qer)) {
    if (qer->update(update, cause_value)) {
      return true;
    }
    return false;
  }
  cause_value = pfcp::CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  return false;
}

//------------------------------------------------------------------------------
/**
 * Update URR
 */
bool pfcp_session::update(
    const pfcp::update_urr& update, uint8_t& cause_value) {
  std::shared_ptr<pfcp::pfcp_urr> urr = {};
  if (get(update.urr_id.urr_id, urr)) {
    if (urr->update(update, cause_value)) {
      return true;
    }
    return false;
  }
  cause_value = pfcp::CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::create(
    const pfcp::create_far& cr_far, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not cr_far.far_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_FAR_ID;
    return false;
  }
  if (not cr_far.apply_action.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_APPLY_ACTION;
    return false;
  }
  if (cr_far.apply_action.second.forw) {
    if (not cr_far.forwarding_parameters.first) {
      // should be caught in lower layer
      cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
      offending_ie      = PFCP_IE_FORWARDING_PARAMETERS;
      return false;
    }
  }
  if (cr_far.apply_action.second.dupl) {
    if (not cr_far.duplicating_parameters.first) {
      // should be caught in lower layer
      cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
      offending_ie      = PFCP_IE_DUPLICATING_PARAMETERS;
      return false;
    }
  }
  pfcp_far* far                  = new pfcp_far(cr_far);
  std::shared_ptr<pfcp_far> sfar = std::shared_ptr<pfcp_far>(far);
  add(sfar);
  return true;
}

//------------------------------------------------------------------------------
bool pfcp_session::create(
    const pfcp::create_pdr& cr_pdr, pfcp::cause_t& cause,
    uint16_t& offending_ie, pfcp::fteid_t& allocated_fteid) {
  if (not cr_pdr.pdr_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_PDR_ID;
    return false;
  }
  if (not cr_pdr.precedence.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_PRECEDENCE;
    return false;
  }
  if (not cr_pdr.pdi.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_PDI;
    return false;
  }

  pfcp_pdr* pdr                  = new pfcp_pdr(cr_pdr);
  std::shared_ptr<pfcp_pdr> spdr = std::shared_ptr<pfcp_pdr>(pdr);

  if ((spdr->pdi.first) && (spdr->pdi.second.source_interface.first)) {
    if (spdr->pdi.second.source_interface.second.interface_value ==
        INTERFACE_VALUE_ACCESS) {
      // Have to chose an TEID for F-TEID
      if (spdr->pdi.second.local_fteid.first) {
        pfcp_switch_inst->create_teid(
            spdr->pdi.second.local_fteid.second.teid, seid, spdr);
        allocated_fteid = spdr->pdi.second.local_fteid.second;
      }
    } else if (
        spdr->pdi.second.source_interface.second.interface_value ==
        INTERFACE_VALUE_CORE) {
      if ((spdr->pdi.second.ue_ip_address.first) &&
          (spdr->pdi.second.ue_ip_address.second.v4)) {
        pfcp_switch_inst->add_pfcp_dl_pdr_by_ue_ip(
            be32toh(spdr->pdi.second.ue_ip_address.second.ipv4_address.s_addr),
            seid, spdr);
      }
    }
  }

  add(spdr);
  return true;
}

//------------------------------------------------------------------------------
bool pfcp_session::create(
    const pfcp::create_qer& cr_qer, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not cr_qer.qer_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_QER_ID;
    return false;
  }
  if (not cr_qer.gate_status.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_GATE_STATUS;
    return false;
  }

  pfcp_qer* qer                  = new pfcp_qer(cr_qer);
  std::shared_ptr<pfcp_qer> sqer = std::shared_ptr<pfcp_qer>(qer);
  add(sqer);
  return true;
}

//------------------------------------------------------------------------------
/**
 * Create URR
 */
bool pfcp_session::create(
    const pfcp::create_urr& cr_urr, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not cr_urr.urr_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_URR_ID;
    return false;
  }
  if (not cr_urr.measurement_method.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_MEASUREMENT_METHOD;
    return false;
  }

  pfcp_urr* urr                  = new pfcp_urr(cr_urr);
  std::shared_ptr<pfcp_urr> surr = std::shared_ptr<pfcp_urr>(urr);
  add(surr);
  return true;
}

//------------------------------------------------------------------------------
bool pfcp_session::remove(
    const pfcp::remove_far& rm_far, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  uint8_t cv = 0;
  if (not rm_far.far_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_FAR_ID;
    return false;
  }
  if (remove(rm_far.far_id.second, cv)) {
    return true;
  }
  cause.cause_value = cv;
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::remove(
    const pfcp::remove_pdr& rm_pdr, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  uint8_t cv = 0;
  if (not rm_pdr.pdr_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_PDR_ID;
    return false;
  }
  if (remove(rm_pdr.pdr_id.second, cv)) {
    return true;
  }
  cause.cause_value = cv;
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::remove(
    const pfcp::remove_qer& rm_qer, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  uint8_t cv = 0;
  if (not rm_qer.qer_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_QER_ID;
    return false;
  }
  if (remove(rm_qer.qer_id.second, cv)) {
    return true;
  }
  cause.cause_value = cv;
  return false;
}

//------------------------------------------------------------------------------
/**
 * Remove URR
 */
bool pfcp_session::remove(
    const pfcp::remove_urr& rm_urr, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  uint8_t cv = 0;
  if (not rm_urr.urr_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_URR_ID;
    return false;
  }
  if (remove(rm_urr.urr_id.second, cv)) {
    return true;
  }
  cause.cause_value = cv;
  return false;
}

//------------------------------------------------------------------------------
void pfcp_session::cleanup() {
  for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::iterator it = pdrs.begin();
       it != pdrs.end(); ++it) {
    if (((*it)->pdi.first) && ((*it)->pdi.second.source_interface.first)) {
      if ((*it)->pdi.second.source_interface.second.interface_value ==
          INTERFACE_VALUE_ACCESS) {
        if ((*it)->pdi.second.local_fteid.first) {
          pfcp_switch_inst->remove_pfcp_ul_pdrs_by_up_teid(
              (*it)->pdi.second.local_fteid.second.teid);
        }
      } else if (
          (*it)->pdi.second.source_interface.second.interface_value ==
          INTERFACE_VALUE_CORE) {
        if (((*it)->pdi.second.ue_ip_address.first) &&
            ((*it)->pdi.second.ue_ip_address.second.v4)) {
          pfcp_switch_inst->remove_pfcp_dl_pdrs_by_ue_ip(be32toh(
              (*it)->pdi.second.ue_ip_address.second.ipv4_address.s_addr));
        }
      }
    }
  }
  fars.clear();
  pdrs.clear();
  qers.clear();
  urrs.clear();
}

//------------------------------------------------------------------------------
std::string pfcp_session::to_string() const {
  std::string s = {};
  for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::const_iterator it_pdr =
           pdrs.begin();
       it_pdr != pdrs.end(); ++it_pdr) {
    s.append(fmt::format("|{:016x}", seid));  // TODO continue this line
    std::shared_ptr<pfcp::pfcp_pdr> pdr = *it_pdr;
    std::shared_ptr<pfcp::pfcp_far> far = {};

    s.append(fmt::format("|{:04x}", pdr->pdr_id.rule_id));
    s.append(fmt::format("|{:08x}", pdr->far_id.second.far_id));
    if (pdr->precedence.first) {
      std::string f = fmt::format("|{:08x}", pdr->precedence.second.precedence);
      s.append(f);
    } else {
      s.append("|no prece");
    }
    if (pdr->pdi.first) {
      if (pdr->pdi.second.source_interface.first) {
        switch (pdr->pdi.second.source_interface.second.interface_value) {
          case pfcp::INTERFACE_VALUE_ACCESS:
            s.append("|ACC>");
            break;
          case pfcp::INTERFACE_VALUE_CORE:
            s.append("|COR>");
            break;
          case pfcp::INTERFACE_VALUE_SGI_LAN_N6_LAN:
            s.append("|LAN>");
            break;
          case pfcp::INTERFACE_VALUE_CP_FUNCTION:
            s.append("|CPF>");
            break;
          case pfcp::INTERFACE_VALUE_LI_FUNCTION:
            s.append("|LIF>");
            break;
          default:
            s.append("| ? >");
        }
      } else {
        s.append("| ? >");
      }
    } else {
      s.append("| ? >");
    }

    if ((pdr->far_id.first) && (get(pdr->far_id.second.far_id, far))) {
      char c = '-';
      if (far->apply_action.dupl) {
        c = '=';
      }
      s.append(1, c);
      if (far->apply_action.nocp) {
        s.append("N");
      } else {
        s.append(1, c);
      }
      if (far->apply_action.buff) {
        s.append("B");
      } else {
        s.append(1, c);
      }
      if (far->apply_action.drop) {
        s.append("X");
      } else {
        s.append(1, c);
      }
      if (far->apply_action.forw) {
        if ((far->forwarding_parameters.first) &&
            (far->forwarding_parameters.second.destination_interface.first)) {
          switch (far->forwarding_parameters.second.destination_interface.second
                      .interface_value) {
            case pfcp::INTERFACE_VALUE_ACCESS:
              s.append(">ACC");
              break;
            case pfcp::INTERFACE_VALUE_CORE:
              s.append(">COR");
              break;
            case pfcp::INTERFACE_VALUE_SGI_LAN_N6_LAN:
              s.append(">LAN");
              break;
            case pfcp::INTERFACE_VALUE_CP_FUNCTION:
              s.append(">CPF");
              break;
            case pfcp::INTERFACE_VALUE_LI_FUNCTION:
              s.append(">LIF");
              break;
            default:
              s.append("> ? ");
          }
        }
      } else {
        s.append("> ? ");
      }
      if ((far->forwarding_parameters.first) &&
          (far->forwarding_parameters.second.outer_header_creation.first)) {
        switch (far->forwarding_parameters.second.outer_header_creation.second
                    .outer_header_creation_description) {
          case pfcp::OUTER_HEADER_CREATION_GTPU_UDP_IPV4: {
            s.append("|GTPU_UDP_IPV4:");
            std::string ip = oai::utils::conv::toString(
                far->forwarding_parameters.second.outer_header_creation.second
                    .ipv4_address);
            ip.resize(INET_ADDRSTRLEN, ' ');
            s.append(ip);
            s.append(fmt::format(
                ":{:08x}", far->forwarding_parameters.second
                               .outer_header_creation.second.teid));
          } break;
          case pfcp::OUTER_HEADER_CREATION_GTPU_UDP_IPV6: {
            s.append("|GTPU_UDP_IPV6:");
            std::string ip = oai::utils::conv::toString(
                far->forwarding_parameters.second.outer_header_creation.second
                    .ipv6_address);
            ip.resize(INET_ADDRSTRLEN, ' ');
            s.append(fmt::format(
                ":{:08x}", far->forwarding_parameters.second
                               .outer_header_creation.second.teid));
          } break;
          case pfcp::OUTER_HEADER_CREATION_UDP_IPV4: {
            s.append("|UDP_IPV4     :");
            std::string ip = oai::utils::conv::toString(
                far->forwarding_parameters.second.outer_header_creation.second
                    .ipv4_address);
            ip.resize(INET_ADDRSTRLEN, ' ');
            s.append(ip);
            s.append(9, ' ');
          } break;
          case pfcp::OUTER_HEADER_CREATION_UDP_IPV6: {
            s.append("|UDP_IPV6     :");
            std::string ip = oai::utils::conv::toString(
                far->forwarding_parameters.second.outer_header_creation.second
                    .ipv6_address);
            ip.resize(INET_ADDRSTRLEN, ' ');
            s.append(ip);
            s.append(9, ' ');
          } break;
          default:
            s.append("|BAD_VALUE    ");
            std::string ip = {};
            ip.resize(INET_ADDRSTRLEN, ' ');
            s.append(ip);
            s.append(9, ' ');
        }
      } else {
        s.append("|none          ");
        std::string ip = {};
        ip.resize(INET_ADDRSTRLEN, ' ');
        s.append(ip);
        s.append(9, ' ');
      }
    }
    if (pdr->outer_header_removal.first) {
      switch (
          pdr->outer_header_removal.second.outer_header_removal_description) {
        case OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4: {
          s.append("|GTPU_UDP_IPV4");
          s.append(
              fmt::format(":{:08x}", pdr->pdi.second.local_fteid.second.teid));
        } break;
        case OUTER_HEADER_REMOVAL_GTPU_UDP_IPV6: {
          s.append("|GTPU_UDP_IPV6");
          s.append(
              fmt::format(":{:08x}", pdr->pdi.second.local_fteid.second.teid));
        } break;
        case OUTER_HEADER_REMOVAL_UDP_IPV4: {
          s.append("|UDP_IPV4     ");
          s.append(9, ' ');
        } break;
        case OUTER_HEADER_REMOVAL_UDP_IPV6: {
          s.append("|UDP_IPV6     ");
          s.append(9, ' ');
        } break;
        default:
          s.append("|BAD_VALUE    ");
          s.append(9, ' ');
      }
    } else {
      s.append("|none         ");
      s.append(9, ' ');
    }
    s.append("|");
    if (pdr->pdi.first) {
      if (pdr->pdi.second.ue_ip_address.first) {
        std::string ip = {};
        if (pdr->pdi.second.ue_ip_address.second.v4) {
          ip = oai::utils::conv::toString(
              pdr->pdi.second.ue_ip_address.second.ipv4_address);
        }
        ip.resize(INET_ADDRSTRLEN, ' ');
        s.append(ip);
        // TODO IPv6
      }
    } else {
      std::string ip = {};
      ip.resize(INET_ADDRSTRLEN, ' ');
      s.append(ip);
    }
    s.append("|\n");
  }
  s.append(
      "+-----------------------------------------------------------------------"
      "------------------------------------------------------------------------"
      "---------------------------------+\n");
  return s;
}