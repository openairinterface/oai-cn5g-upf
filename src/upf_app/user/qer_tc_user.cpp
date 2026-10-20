/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "qer_tc_user.h"
#include <bpf/bpf.h>
#include <algorithm>
#include <optional>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces_types.h"
#include "logger.hpp"
#include "helpers/GetNicInformation.hpp"
#include "helpers/CmdRunner.hpp"
#include "utils/net_utils.hpp"
#include "utils/bpf_utils.hpp"
#include "UserPlaneComponent.h"
#include "rule_apply_error.h"
// #include "sdf_filter.h"
#include "sdf_types.h"
#include "startup_banner.hpp"
#include "number_utils.hpp"

using namespace oai::utils::bpf;
using namespace oai::utils::net;
using namespace oai::utils;

//------------------------------------------------------------------------------
void QERTCProgram::ConfigureQerMaps(struct qer_tc_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in ConfigureQerMaps");
    return;
  }

  const uint32_t max_ifaces   = upf::GetMaxUpfInterfaces();
  const uint32_t max_redirect = upf::GetMaxUpfRedirectInterfaces();

  int num_ifaces = CountAvailableInterfaces();
  if (max_ifaces > static_cast<uint32_t>(num_ifaces)) {
    Logger::upf_app().warn(
        "Configured max_upf_interfaces (%u) exceeds available system "
        "interfaces (%d). Clamping to %d.",
        max_ifaces, num_ifaces, num_ifaces);
  }

  if (max_redirect > max_ifaces) {
    Logger::upf_app().error(
        "Invalid config: max_upf_redirect_interfaces (%u) cannot exceed "
        "max_upf_interfaces (%u).",
        max_redirect, max_ifaces);
    throw std::runtime_error(
        "Invalid UPF configuration (redirect > interfaces)");
  }

  bool ok = ConfigureMapMaxEntries(
      skel->maps.egress_ifindex, "egress_ifindex", max_redirect);

  if (!ok) {
    Logger::upf_app().error("egress_ifindex BPF map configuration failed");
    throw std::runtime_error("QER Program map configuration failed");
  }

  /* qer_tc_kern.c does not declare MAX_UPF_INTERFACES /
   * MAX_UPF_REDIRECT_INTERFACES in its .rodata (those came from
   * interfaces_maps.h, which qer_tc_kern.c no longer includes -- it does not
   * use any of upf_interface_map / arp_table_map / redirect_interfaces_map).
   * The egress_ifindex map is sized above via ConfigureMapMaxEntries. */
}

//------------------------------------------------------------------------------
QERTCProgram::QERTCProgram()
    : BPFProgram(),
      default_class_handle_(65535),
      default_class_rate_(1024),
      default_class_ceil_(2048),
      r2q_root_(1000) {
  Logger::upf_app().debug("Initializing QER TC BPF program ...");

  // open lambda: configuration sourced from upf::g_net_cfg
  auto open_fn = [this]() -> qer_tc_kern_c* {
    struct qer_tc_kern_c* skel = qer_tc_kern_c__open();
    if (!skel) {
      Logger::upf_app().error("Failed to open QER TC BPF skeleton");
      return nullptr;
    }

    // Configure map sizes and .rodata constants
    this->ConfigureQerMaps(skel);
    return skel;
  };

  // Initialize lifecycle management
  lifecycle_ = std::make_shared<QerTCProgramLifeCycle>(
      open_fn,
      /* load */ qer_tc_kern_c__load,
      /* attach */ qer_tc_kern_c__attach,
      /* destroy */ qer_tc_kern_c__destroy, "QERTCProgram");
}

//------------------------------------------------------------------------------
QERTCProgram::~QERTCProgram() {
  // Normally a no-op, because owners call TearDown() first. This covers one
  // that drops the program without doing so. The skeleton itself is released
  // by ~ProgramLifeCycle.
  DeleteTcClasses();
}

//------------------------------------------------------------------------------
bool QERTCProgram::NoHtbRootQdisc(const std::string& interface) {
  std::string cmd = fmt::format(
      "tc qdisc show dev {} | awk '/htb/ {{found=1; print 1}} END {{if "
      "(!found) print 0}}'",
      interface);
  uint32_t ret = std::stoi(CmdRunner::exec(cmd).c_str());
  return ret ? false : true;
}

//------------------------------------------------------------------------------
bool QERTCProgram::NoHtbDefaultClass(const std::string& interface) {
  std::string cmd = fmt::format(
      "tc qdisc show dev {} | awk '/htb/ && /default/ {{found=1; print 1}} "
      "END {{if (!found) print 0}}'",
      interface);
  uint32_t ret = std::stoi(CmdRunner::exec(cmd).c_str());
  return ret ? false : true;
}

//------------------------------------------------------------------------------
std::shared_ptr<pfcp::pfcp_qer> QERTCProgram::RetrieveDefaultQerWithDefaultQfi(
    std::vector<std::shared_ptr<pfcp::pfcp_qer>> qers) {
  for (const auto& qer : qers) {
    if (!qer->guaranteed_bitrate.first && !qer->maximum_bitrate.first) {
      return qer;
    }
  }
  return nullptr;
}

//------------------------------------------------------------------------------
void QERTCProgram::BuildPdrMap(
    const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs) {
  pdr_map_.clear();
  for (const auto& pdr : pdrs) {
    if (pdr && pdr->qer_id.first) {
      pdr_map_[pdr->qer_id.second.qer_id] = pdr;
    }
  }
}

//------------------------------------------------------------------------------
std::shared_ptr<pfcp::pfcp_pdr> QERTCProgram::GetPdrByQerId(
    uint32_t qer_id) const {
  auto it = pdr_map_.find(qer_id);
  return (it != pdr_map_.end()) ? it->second : nullptr;
}

//------------------------------------------------------------------------------
bool QERTCProgram::NoTcFilterBpf(const std::string& interface) {
  std::string cmd = fmt::format(
      "tc filter show dev {} | awk '/bpf/ {{found=1; print 1}} END {{if "
      "(!found) print 0}}'",
      interface);
  uint32_t ret = std::stoi(CmdRunner::exec(cmd).c_str());
  return ret ? false : true;
}

//------------------------------------------------------------------------------
void QERTCProgram::Setup(
    uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> qers,
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs) {
  const std::string udp_iface = upf::GetN6Iface();
  const std::string gtp_iface = upf::GetN3Iface();

  const uint32_t default_rate = NicInformationGetter::retrieveRate(gtp_iface);
  const uint32_t max_rate     = default_rate;
  const uint32_t default_ceil = NicInformationGetter::retrieveCeil(gtp_iface);
  const uint32_t max_ceil     = default_ceil;

  // A failure that is not one QER's own (the program, the root qdisc, the
  // filters, the PDU session class) is reported against the session's first
  // QER: without it none of the session's QERs is enforced.
  const uint32_t session_qer_id =
      qers.empty() ? 0 : qers.front()->qer_id.second.qer_id;
  std::optional<RuleApplyError> failure;
  const auto fail = [&](uint32_t qer_id, const std::string& why) {
    if (!failure) {
      failure.emplace(
          pfcp::FAILED_RULE_ID_TYPE_QER, qer_id ? qer_id : session_qer_id, why);
    }
  };

  // open(), load() and attach() are no-ops once done, so a later Setup() for
  // the same session reuses the program it loaded the first time
  try {
    skeleton_ = lifecycle_->open();
    InitializeMaps();
    lifecycle_->load();
    lifecycle_->attach();

    uint32_t udp_interface_index = if_nametoindex(udp_iface.c_str());
    uint32_t gtp_interface_index = if_nametoindex(gtp_iface.c_str());

    if (udp_interface_index == 0 || gtp_interface_index == 0) {
      Logger::upf_app().error("Failed to retrieve interface indices");
      throw std::runtime_error("Invalid network interface index");
    }

    uint32_t uplink_id   = static_cast<uint32_t>(FlowDirection::UPLINK);
    uint32_t downlink_id = static_cast<uint32_t>(FlowDirection::DOWNLINK);

    egress_ifindex_map_->Update(uplink_id, udp_interface_index, BPF_ANY);
    egress_ifindex_map_->Update(downlink_id, gtp_interface_index, BPF_ANY);
  } catch (const std::exception& e) {
    throw RuleApplyError(
        pfcp::FAILED_RULE_ID_TYPE_QER, session_qer_id,
        fmt::format("QER TC program not loaded: {}", e.what()));
  }

  // TearDown() deletes the classes recorded below from this interface
  tc_iface_ = gtp_iface;

  if (!qers.empty()) {
    // Start QoS Setup Banner
    LogQosSetupStart(seid, gtp_iface);

    Logger::upf_app().info(
        "  ┌─ N6 Interface (Non-GTP): %s", udp_iface.c_str());
    Logger::upf_app().info(
        "  └─ N3 Interface (GTP):     %s", gtp_iface.c_str());

    // Configure Root Qdisc if not already present
    if (NoHtbRootQdisc(gtp_iface)) {
      Logger::upf_app().info(
          "  ┌─ Creating Root HTB Qdisc on %s", gtp_iface.c_str());
      Logger::upf_app().info(
          "  │  • Default Class: %u", GetDefaultClassHandle());
      Logger::upf_app().info("  │  • r2q Parameter: %u", GetR2qRoot());
      Logger::upf_app().debug(
          " │  • Max DL Rate:   %s kbps", FormatNumber(max_rate).c_str());
      Logger::upf_app().debug(
          " │  • Max DL Ceil:   %s kbps", FormatNumber(max_ceil).c_str());

      const std::string cmd = fmt::format(
          "tc qdisc add dev {} root handle 1:0 htb default {} r2q {}",
          gtp_iface, GetDefaultClassHandle(), GetR2qRoot());

      if (system(cmd.c_str()) != 0) {
        Logger::upf_app().error(
            "  └─ ✗ Failed to create root qdisc %s on %s", cmd.c_str(),
            gtp_iface.c_str());
        fail(0, fmt::format("root HTB qdisc not created on {}", gtp_iface));
      } else {
        Logger::upf_app().info(
            "  └─ ✓ Root qdisc created successfully on interface: %s",
            gtp_iface.c_str());
      }
    } else {
      Logger::upf_app().debug(
          "HTB Root qdisc on interface: %s, already created",
          gtp_iface.c_str());
    }
  }

  // Bring the session's classes in line with its QERs. With none left, this
  // deletes every class it had.
  BuildPdrMap(pdrs);
  std::vector<QosFlowInfo> qos_flows;
  const std::vector<TcClass> wanted =
      qers.empty() ? std::vector<TcClass>{} :
                     BuildTcClasses(seid, qers, max_rate, qos_flows);
  const std::set<uint32_t> failed_qer_ids = ApplyTcClasses(wanted);
  for (uint32_t qer_id : failed_qer_ids) {
    fail(
        qer_id,
        qer_id ?
            fmt::format(
                "HTB class of QER {} not applied on {}", qer_id, gtp_iface) :
            fmt::format("PDU session class not applied on {}", gtp_iface));
  }

  if (!qers.empty()) {
    // Attach TC BPF filter (silent)
    if (NoTcFilterBpf(gtp_iface)) {
      Logger::upf_app().info(
          "Attach Section tc_filter_traffic to gtp interface");
      const std::string cmd = fmt::format(
          "tc filter add dev {} parent 1:0 protocol ip bpf obj "
          "/openair-upf/bin/qer_tc_kern.c.o classid 1: direct-action",
          gtp_iface.c_str());
      if (system(cmd.c_str()) != 0) {
        Logger::upf_app().error("Failed to attach TC BPF filter");
        fail(0, fmt::format("TC BPF filter not attached to {}", gtp_iface));
      }
    }

    // Attach TC redirect to UDP interface
    Logger::upf_app().info("Attach Section tc_redirect to udp interface");
    try {
      lifecycle_->tcAttachIngress("tc_redirect_traffic", udp_iface.c_str());
    } catch (const std::exception& e) {
      fail(
          0, fmt::format(
                 "TC redirect not attached to {}: {}", udp_iface, e.what()));
    }

    // Display QoS Flow Table, without the flows whose class failed
    qos_flows.erase(
        std::remove_if(
            qos_flows.begin(), qos_flows.end(),
            [&failed_qer_ids](const QosFlowInfo& flow) {
              return failed_qer_ids.count(flow.qer_id) > 0;
            }),
        qos_flows.end());
    if (!qos_flows.empty()) {
      DisplayQosFlowTable(seid, qos_flows);
    }

    // End QoS Setup Banner
    LogQosSetupComplete(seid, qos_flows.size(), failure.has_value());
  }

  // Everything that could be applied has been: the caller still has to learn
  // that the rest was not
  if (failure) {
    throw *failure;
  }
}

//------------------------------------------------------------------------------
std::vector<QERTCProgram::TcClass> QERTCProgram::BuildTcClasses(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_qer>>& qers,
    uint32_t session_rate_kbps, std::vector<QosFlowInfo>& flows) {
  std::vector<TcClass> classes;

  // PDU session class, the parent of every QoS flow class of the session
  const uint16_t casted_seid = static_cast<uint16_t>(seid);
  const uint64_t rate_bytes  = ((uint64_t) session_rate_kbps * 1000) / 8;
  const uint32_t pdu_quantum = rate_bytes / GetR2qRoot();
  classes.push_back(
      {casted_seid, 0, session_rate_kbps, 0, pdu_quantum, 0,
       "PDU session class"});

  std::shared_ptr<pfcp::pfcp_qer> default_qer =
      RetrieveDefaultQerWithDefaultQfi(qers);

  if (default_qer) {
    Logger::upf_app().debug(
        "  → Default QoS Flow detected: QER=%u, QFI=%u",
        default_qer->qer_id.second.qer_id, default_qer->qos_flow_id.second.qfi);
  }

  std::set<uint8_t> qfis;
  for (const auto& qer : qers) {
    const uint32_t qer_id = qer->qer_id.second.qer_id;
    const uint8_t qfi     = qer->qos_flow_id.second.qfi;
    const uint16_t minor  = generate_minor_id(seid, qfi);

    // One class per QoS flow. A QER is listed once per downlink PDR using
    // it, and several QERs may share a QFI: the first one shapes the flow.
    if (!qfis.insert(qfi).second) {
      Logger::upf_app().debug(
          "  → QER %u: QFI %u already shaped by an earlier QER", qer_id, qfi);
      continue;
    }

    // Default QoS flow: a default class under the session class, and the
    // flow's own class under that
    if (qer == default_qer) {
      const uint16_t default_minor = (GetDefaultClassHandle() - minor) % 10000;
      const uint64_t default_rate_bytes =
          ((uint64_t) GetDefaultClassRate() * 1000) / 8;
      const uint32_t default_quantum = default_rate_bytes / GetR2qRoot();

      classes.push_back(
          {default_minor, casted_seid, GetDefaultClassRate(),
           GetDefaultClassCeil(), default_quantum, qer_id, "default class"});
      classes.push_back(
          {minor, default_minor, GetDefaultClassRate(), GetDefaultClassCeil(),
           default_quantum, qer_id, "PFIFO default class"});

      QosFlowInfo flow;
      flow.qer_id           = qer_id;
      flow.qfi              = qfi;
      flow.rate_kbps        = GetDefaultClassRate();
      flow.ceil_kbps        = GetDefaultClassCeil();
      flow.class_id         = default_minor;
      flow.flow_description = "Default QoS Flow";
      flows.push_back(flow);
      continue;
    }

    // GBR/MBR QoS flow
    if (qer->maximum_bitrate.first) {
      uint64_t dl_ceil = std::max(qer->maximum_bitrate.second.dl_mbr, 1UL);
      uint64_t dl_rate = 1;

      if (qer->guaranteed_bitrate.first) {
        // GBR present: use the SMF-provided GBR value
        dl_rate = std::max(qer->guaranteed_bitrate.second.dl_gbr, 1UL);
      } else {
        // GBR absent: fallback to 80% of MBR
        dl_rate = std::max(static_cast<unsigned long>(dl_ceil * 0.8), 1UL);
        Logger::upf_app().warn("QoS Flow missing GBR: set it to 0.8 x MBR");
      }

      classes.push_back(
          {minor, casted_seid, dl_rate, dl_ceil, 0, qer_id, "QoS flow class"});

      QosFlowInfo flow;
      flow.qer_id    = qer_id;
      flow.qfi       = qfi;
      flow.rate_kbps = dl_rate;
      flow.ceil_kbps = dl_ceil;
      flow.class_id  = minor;

      // Get flow description from associated PDR
      auto pdr = GetPdrByQerId(qer_id);
      if (pdr) {
        pfcp::pdi pdi;
        if (pdr->get(pdi)) {
          pfcp::sdf_filter_t sdf;
          if (pdi.get(sdf) && sdf.fd && sdf.length_of_flow_description > 0) {
            flow.flow_description = sdf.flow_description;
          }
        }
      }
      if (flow.flow_description.empty()) {
        flow.flow_description = "permit out ip from any to any";
      }
      flows.push_back(flow);
    }
  }

  return classes;
}

//------------------------------------------------------------------------------
std::set<uint32_t> QERTCProgram::ApplyTcClasses(
    const std::vector<TcClass>& wanted) {
  std::set<uint32_t> failed_qer_ids;

  const auto find = [](auto& classes, uint16_t minor) {
    return std::find_if(
        classes.begin(), classes.end(),
        [minor](const TcClass& tc_class) { return tc_class.minor == minor; });
  };

  // Classes that must go: no longer wanted, or wanted under another parent,
  // which HTB cannot change in place. HTB also refuses to delete a class that
  // still has children, so the children of one that goes, go too.
  std::set<uint16_t> doomed;
  for (const auto& installed : classes_) {
    auto it = find(wanted, installed.minor);
    if (it == wanted.end() || it->parent != installed.parent) {
      doomed.insert(installed.minor);
    }
  }
  for (bool grew = true; grew;) {
    grew = false;
    for (const auto& installed : classes_) {
      if (!doomed.count(installed.minor) && doomed.count(installed.parent)) {
        doomed.insert(installed.minor);
        grew = true;
      }
    }
  }

  // Every class was recorded after its parent, so walking backwards deletes
  // children first. One that fails to go stays recorded, for TearDown().
  std::vector<TcClass> kept;
  for (auto it = classes_.rbegin(); it != classes_.rend(); ++it) {
    if (doomed.count(it->minor)) {
      if (DeleteTcClass(*it)) continue;
      failed_qer_ids.insert(it->qer_id);
    }
    kept.push_back(*it);
  }
  classes_.assign(kept.rbegin(), kept.rend());

  // Change the classes that stay and add the new ones, parents first
  std::set<uint16_t> seen;
  for (const auto& tc_class : wanted) {
    if (!seen.insert(tc_class.minor).second) {
      Logger::upf_app().error(
          "  └─ ✗ %s 1:%x of QER %u collides with another class of this "
          "session",
          tc_class.role.c_str(), tc_class.minor, tc_class.qer_id);
      failed_qer_ids.insert(tc_class.qer_id);
      continue;
    }

    auto installed = find(classes_, tc_class.minor);
    if (installed == classes_.end()) {
      if (WriteTcClass(tc_class, /* update */ false)) {
        classes_.push_back(tc_class);
      } else {
        failed_qer_ids.insert(tc_class.qer_id);
      }
    } else if (installed->parent != tc_class.parent) {
      // Only left over when deleting it under its old parent failed above
      failed_qer_ids.insert(tc_class.qer_id);
    } else if (
        installed->rate_kbps != tc_class.rate_kbps ||
        installed->ceil_kbps != tc_class.ceil_kbps ||
        installed->quantum != tc_class.quantum) {
      if (WriteTcClass(tc_class, /* update */ true)) {
        *installed = tc_class;
      } else {
        failed_qer_ids.insert(tc_class.qer_id);
      }
    } else {
      // Unchanged; it may now belong to another QER of the session
      *installed = tc_class;
    }
  }

  return failed_qer_ids;
}

//------------------------------------------------------------------------------
bool QERTCProgram::WriteTcClass(const TcClass& tc_class, bool update) {
  // The root qdisc is "1:", a class is "1:<minor>"
  const std::string parent =
      tc_class.parent ? fmt::format("1:{:x}", tc_class.parent) : "1:";
  std::string cmd = fmt::format(
      "tc class {} dev {} parent {} classid 1:{:x} htb rate {}kbit",
      update ? "replace" : "add", tc_iface_, parent, tc_class.minor,
      tc_class.rate_kbps);
  if (tc_class.ceil_kbps) {
    cmd += fmt::format(" ceil {}kbit", tc_class.ceil_kbps);
  }
  if (tc_class.quantum) {
    cmd += fmt::format(" quantum {}", tc_class.quantum);
  }

  Logger::upf_app().info(
      "  ┌─ %s %s 1:%x, child of %s (QER %u)", update ? "Updating" : "Creating",
      tc_class.role.c_str(), tc_class.minor, parent.c_str(), tc_class.qer_id);
  Logger::upf_app().info(
      "  │  • Rate: %s kbps", FormatNumber(tc_class.rate_kbps).c_str());
  if (tc_class.ceil_kbps) {
    Logger::upf_app().info(
        "  │  • Ceil: %s kbps", FormatNumber(tc_class.ceil_kbps).c_str());
  }

  if (system(cmd.c_str()) != 0) {
    Logger::upf_app().error(
        "  └─ ✗ Failed to %s %s 1:%x: %s", update ? "update" : "create",
        tc_class.role.c_str(), tc_class.minor, cmd.c_str());
    return false;
  }

  Logger::upf_app().info(
      "  └─ ✓ %s 1:%x %s successfully", tc_class.role.c_str(), tc_class.minor,
      update ? "updated" : "created");
  return true;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> QERTCProgram::GetMaps() {
  return maps_;
}

//------------------------------------------------------------------------------
void QERTCProgram::TearDown() {
  DeleteTcClasses();
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void QERTCProgram::DeleteTcClasses() {
  // Reverse creation order: every parent was created before its children,
  // and HTB refuses to delete a class that still has children.
  for (auto it = classes_.rbegin(); it != classes_.rend(); ++it) {
    DeleteTcClass(*it);
  }
  classes_.clear();
}

//------------------------------------------------------------------------------
bool QERTCProgram::DeleteTcClass(const TcClass& tc_class) {
  const std::string cmd = fmt::format(
      "tc class del dev {} classid 1:{:x}", tc_iface_, tc_class.minor);
  if (system(cmd.c_str()) != 0) {
    Logger::upf_app().warn(
        "Failed to delete tc class 1:%x on %s", tc_class.minor,
        tc_iface_.c_str());
    return false;
  }
  Logger::upf_app().info(
      "  ✓ %s 1:%x deleted (QER %u)", tc_class.role.c_str(), tc_class.minor,
      tc_class.qer_id);
  return true;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> QERTCProgram::Get5GQoSFlowParamsMap() const {
  return qos_flow_params_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> QERTCProgram::GetEgressIfindexMap() const {
  return egress_ifindex_map_;
}

//------------------------------------------------------------------------------
void QERTCProgram::InitializeMaps() {
  // Store all maps available in the program
  maps_ = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);

  egress_ifindex_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("egress_ifindex"));
}
