/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */
// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Rewritten to use dedicated program class instances.
 *
 *              Primary program selection (corrected from previous version):
 *                IP PDU  -> n3_ is primary.
 *                ETH PDU -> n3_eth_ is primary.
 *              n3_ is NOT instantiated in ETH PDU mode. Both kernel programs
 *              include tail_call_dispatcher.h so either can be primary.
 *
 *              Setup() logic:
 *                Step 1: Instantiate entry programs based on pdu_type.
 *                Step 2: Instantiate stage programs based on pdu_type +
 *                        feature flags.
 *                Step 3: Open + load the primary entry program only.
 *                Step 4: ShareMaps(primary, all_others).
 *                Step 5: Each remaining program calls its own Setup()/Load().
 *                Step 6: InitializeMaps from the primary skeleton.
 *                Step 7: Attach + link the primary entry program.
 *                Step 8: PopulateProgramArray.
 *
 *              TODOs resolved (from n3_entry_user.cpp):
 *                TODO 1: GetTotalMapCount() sums over all non-null programs.
 *                TODO 2: IsNativeXdp() / GetXdpModeString() delegate to
 *                        GetLifeCycle() on the attached entry program.
 *
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol
 *              3GPP TS 23.501          -- 5G System Architecture
 */
// clang-format on

#include "upf_xdp_user.h"
#include "startup_banner.hpp"
#include "tail_call_types.h"
#include "xdp_hook_section.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <stdexcept>
#include <cstring>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_xdp_limits.h"
#include "interfaces_types.h"

/* Section: Constructor / Destructor */

//------------------------------------------------------------------------------
UPF_XDPProgram::UPF_XDPProgram(
    const std::string& gtp_interface, const std::string& non_gtp_interface)
    : BPFProgram(),
      gtp_interface_(gtp_interface),
      non_gtp_interface_(non_gtp_interface) {
  Logger::upf_app().debug(
      "UPF_XDPProgram: created (N3 , N6) : (%s , %s)", gtp_interface_.c_str(),
      non_gtp_interface_.c_str());
}

//------------------------------------------------------------------------------
UPF_XDPProgram::~UPF_XDPProgram() {
  TearDown();
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::Setup(const PipelineFeatureFlags& flags) {
  features_         = flags;
  const bool is_eth = (flags.pdu_type == PduSessionType::Ethernet);

  Logger::upf_app().info("PDU Session type: %s", is_eth ? "Ethernet" : "IP");

  /*  Step 1: Instantiate entry programs
   * Exactly one pair is created based on pdu_type.
   * The first program in each pair becomes "primary" -- it is loaded first
   * so its map FDs are created before ShareMaps() is called.
   *
   * IP PDU:
   *   n3_ is primary (GTP interface). Owns tail_call_progs_map,
   *   packet_context_map, session_rules_enabled_map, mc_stats_map.
   *   n6_ shares those maps via bpf_map__reuse_fd.
   *
   * ETH PDU:
   *   n3_eth_ is primary (GTP interface). Same maps -- it also includes
   *   tail_call_dispatcher.h and stats_maps.h. n3_ is NOT instantiated.
   *   n6_eth_ shares those maps via bpf_map__reuse_fd.
   */
  if (!is_eth) {
    n3_ = std::make_shared<N3EntryProgram>(gtp_interface_);
    n6_ = std::make_shared<N6EntryProgram>(non_gtp_interface_);
  } else {
    n3_eth_ = std::make_shared<N3EthEntryProgram>(gtp_interface_);
    n6_eth_ = std::make_shared<N6EthEntryProgram>(non_gtp_interface_);
  }

  /* Step 2: Instantiate stage programs
   * Session lookup program matches the PDU type.
   * PDR and FAR are always present.
   * QER, URR, BAR, MAR are conditional on feature flags.
   */
  if (!is_eth) {
    sl_ip_ = std::make_shared<SessionLookupIPProgram>();
  } else {
    sl_eth_ = std::make_shared<SessionLookupETHProgram>();
  }

  pdr_ = std::make_shared<PdrMatchProgram>();
  far_ = std::make_shared<FARProgram>();

  if (flags.enable_qer) {
    qer_    = std::make_shared<QERProgram>();
    qer_tc_ = std::make_shared<QERTCProgram>();
  }

  if (flags.enable_urr) urr_ = std::make_shared<URRProgram>();
  if (flags.enable_bar) bar_ = std::make_shared<BARProgram>();
  if (flags.enable_mar) mar_ = std::make_shared<MARProgram>();

  DisplayPipelineCreationTree(flags);

  /* ── Step 1b: Open ALL programs (constructors only store open_fn, never
   *             call it). ConfigureMaps() runs inside each open_fn and sets
   *             bpf_map__set_max_entries() ONLY for maps owned by that program.
   *               far_  owns: upf_interface_map, arp_table_map,
   *                           redirect_interfaces_map
   *               n3_   owns: packet_context_map, tail_call_progs_map,
   *                           session_rules_enabled_map, mc_stats_map
   *             No program sizes a map it does not own.
   */
  far_->GetLifeCycle()->open();
  if (!is_eth) {
    n3_->GetLifeCycle()->open();
    n6_->GetLifeCycle()->open();
  } else {
    n3_eth_->GetLifeCycle()->open();
    n6_eth_->GetLifeCycle()->open();
  }
  if (sl_ip_) sl_ip_->GetLifeCycle()->open();
  if (sl_eth_) sl_eth_->GetLifeCycle()->open();
  pdr_->GetLifeCycle()->open();
  if (qer_) qer_->GetLifeCycle()->open();
  if (urr_) urr_->GetLifeCycle()->open();
  if (bar_) bar_->GetLifeCycle()->open();
  if (mar_) mar_->GetLifeCycle()->open();

  /* ── Step 2: Load far_ FIRST
   *   far_ owns upf_interface_map / arp_table_map / redirect_interfaces_map.
   *   Loading it now creates those kernel maps with the correct max_entries
   *   (set by FARProgram::ConfigureMaps via bpf_map__set_max_entries).
   */
  far_->GetLifeCycle()->load();
  Logger::upf_app().info("UPF_XDPProgram: far_ loaded (map owner)");

  /* ── Step 3: Share far_-owned maps to ALL other programs BEFORE they load.
   *   bpf_map__reuse_fd must be called before bpf_object__load.
   *   Targets: n3_, n6_, sl_ip_, pdr_, qer_, urr_, bar_, mar_
   */
  /* far_ owns: upf_interface_map, arp_table_map, redirect_interfaces_map.
   * Share ONLY these to avoid overwriting maps owned by other programs. */
  const std::initializer_list<const char*> far_owned = {
      "upf_interface_map", "arp_table_map", "redirect_interfaces_map"};
  struct bpf_object* far_obj = far_->GetBpfObject();
  if (!is_eth) {
    ShareMapsOwned(far_obj, n3_->GetBpfObject(), far_owned);
    ShareMapsOwned(far_obj, n6_->GetBpfObject(), far_owned);
  } else {
    ShareMapsOwned(far_obj, n3_eth_->GetBpfObject(), far_owned);
    ShareMapsOwned(far_obj, n6_eth_->GetBpfObject(), far_owned);
  }
  if (sl_ip_) ShareMapsOwned(far_obj, sl_ip_->GetBpfObject(), far_owned);
  if (sl_eth_) ShareMapsOwned(far_obj, sl_eth_->GetBpfObject(), far_owned);
  ShareMapsOwned(far_obj, pdr_->GetBpfObject(), far_owned);
  ShareMapsOwned(far_obj, n3_->GetBpfObject(), far_owned);
  if (qer_) ShareMapsOwned(far_obj, qer_->GetBpfObject(), far_owned);
  if (urr_) ShareMapsOwned(far_obj, urr_->GetBpfObject(), far_owned);
  if (bar_) ShareMapsOwned(far_obj, bar_->GetBpfObject(), far_owned);
  if (mar_) ShareMapsOwned(far_obj, mar_->GetBpfObject(), far_owned);
  Logger::upf_app().debug(
      "ShareMaps: far_-owned maps shared "
      "(upf_interface/arp_table/redirect_interfaces)");

  /* ── Step 4: Load n3_ (primary entry)
   *   n3_ owns packet_context_map, tail_call_progs_map,
   *   session_rules_enabled_map, mc_stats_map.
   *   It reuses far_'s upf_interface_map (reuse_fd done in Step 3).
   */
  if (!is_eth) {
    n3_->GetLifeCycle()->load();
    Logger::upf_app().info("UPF_XDPProgram: n3_entry loaded");
  } else {
    n3_eth_->GetLifeCycle()->load();
    Logger::upf_app().info("UPF_XDPProgram: n3_eth_entry loaded");
  }

  /* ── Step 5: Share n3_-owned maps to ALL other programs BEFORE they load. */
  /* n3_ owns: packet_context_map, tail_call_progs_map,
   *            session_rules_enabled_map, mc_stats_map.
   * Share ONLY these to avoid overwriting maps owned by other programs. */
  const std::initializer_list<const char*> n3_owned = {
      "packet_context_map", "tail_call_progs_map", "session_rules_enabled_map",
      "mc_stats_map"};
  struct bpf_object* primary =
      !is_eth ? n3_->GetBpfObject() : n3_eth_->GetBpfObject();
  if (!is_eth)
    ShareMapsOwned(primary, n6_->GetBpfObject(), n3_owned);
  else
    ShareMapsOwned(primary, n6_eth_->GetBpfObject(), n3_owned);
  if (sl_ip_) ShareMapsOwned(primary, sl_ip_->GetBpfObject(), n3_owned);
  if (sl_eth_) ShareMapsOwned(primary, sl_eth_->GetBpfObject(), n3_owned);
  ShareMapsOwned(primary, pdr_->GetBpfObject(), n3_owned);
  ShareMapsOwned(primary, far_->GetBpfObject(), n3_owned);
  if (qer_) ShareMapsOwned(primary, qer_->GetBpfObject(), n3_owned);
  if (urr_) ShareMapsOwned(primary, urr_->GetBpfObject(), n3_owned);
  if (bar_) ShareMapsOwned(primary, bar_->GetBpfObject(), n3_owned);
  if (mar_) ShareMapsOwned(primary, mar_->GetBpfObject(), n3_owned);
  Logger::upf_app().info("UPF_XDPProgram: map sharing complete");

  /* Step 5: Each remaining program manages its own lifecycle
   * The secondary entry program calls Setup() -- its full lifecycle:
   *   open(idempotent) + InitializeMaps + load + attach + link.
   * Stage programs call Setup() -- their public program-level lifecycle:
   *   open(idempotent) + InitializeMaps + load.
   *   (Their session-level Setup(seid, ...) is called by SessionProgramManager
   *    later, not here.)
   * qer_: XDP gate-check -- normal stage program Setup().
   * qer_tc_: TC-BPF -- no program-level Setup() here.
   *   QERTCProgram::Setup(seid, qers, pdrs) is called per-session
   *   by SessionProgramManager when a session has QER rules.
   */
  if (!is_eth) {
    n6_->Setup();
  } else {
    n6_eth_->Setup();
  }

  if (sl_ip_) sl_ip_->Setup();
  if (sl_eth_) sl_eth_->Setup();

  pdr_->Setup();
  far_->Setup();

  if (qer_) qer_->Setup();
  if (urr_) urr_->Setup();
  if (bar_) bar_->Setup();
  if (mar_) mar_->Setup();

  DisplayPipelineLoadTree(BuildPipelineLoadInfo(flags));
  Logger::upf_app().info("UPF_XDPProgram: all programs loaded");

  /* Step 6: Wrap the primary skeleton's 4 infrastructure maps
   * tail_call_progs_map, packet_context_map, session_rules_enabled_map,
   * mc_stats_map -- present in both n3_entry and n3_eth_entry skeletons.
   */
  struct bpf_object_skeleton* primary_skel =
      !is_eth ? n3_->GetSkeleton() : n3_eth_->GetSkeleton();
  InitializeMaps(primary_skel);

  /* Grab upf_interface_map from the program that owns interfaces_maps.h.
   * IP PDU path: owned by FARProgram (xdp_far_apply_kern includes it).
   * ETH PDU path: owned by N6EthEntryProgram (already exposed via getter).
   */
  /* far_ owns upf_interface_map for BOTH IP and ETH paths.
   * Always retrieve it from far_->GetBpfObject(). */
  {
    struct bpf_map* m =
        bpf_object__find_map_by_name(far_->GetBpfObject(), "upf_interface_map");
    if (m) {
      upf_iface_map_ = std::make_shared<BPFMap>(m, "upf_interface_map");
      Logger::upf_app().info(
          "TRACE upf_iface_map_ set from far_: fd=%d  max=%u", bpf_map__fd(m),
          bpf_map__max_entries(m));
    } else {
      Logger::upf_app().warn(
          "Setup: upf_interface_map not found in FAR object");
    }
  }

  /* Step 7: Complete the PRIMARY entry program's lifecycle
   * The primary was opened+loaded manually in Step 3. Now attach and link
   * it to complete its lifecycle. The secondary already did its full
   * lifecycle via Setup() in Step 5 (open+InitMaps+load+attach+link).
   * upf_interface_map is populated by CreateUpfInterfaceMapEntry below
   * for both IP and ETH paths. far_ is the owner for both paths.
   */
  if (!is_eth) {
    Logger::upf_app().info(
        "UPF_XDPProgram: attaching IP PDU primary (n3_entry)");
    n3_->GetLifeCycle()->attach();
    n3_->GetLifeCycle()->link(
        XDPSection::Uplink_IP_PDU_SESSION, gtp_interface_.c_str());
    CreateUpfInterfaceMapEntry(N3_INTERFACE);
    CreateUpfInterfaceMapEntry(N6_INTERFACE);
    CreateUpfInterfaceMapEntry(N4_INTERFACE);
  } else {
    Logger::upf_app().info(
        "UPF_XDPProgram: attaching ETH PDU primary (n3_eth_entry)");
    n3_eth_->GetLifeCycle()->attach();
    n3_eth_->GetLifeCycle()->link(
        XDPSection::Uplink_ETH_PDU_SESSION, gtp_interface_.c_str());
    CreateUpfInterfaceMapEntry(N3_INTERFACE);
    CreateUpfInterfaceMapEntry(N6_INTERFACE);
    CreateUpfInterfaceMapEntry(N4_INTERFACE);
    /* n6_eth_ interface maps already populated inside n6_eth_->Setup() */
  }

  /* Step 8: Populate tail_call_progs_map
   */
  PopulateProgramArray(flags);

  Logger::upf_app().info("UPF_XDPProgram::Setup complete");
}

/* Section: Map sharing */

//------------------------------------------------------------------------------
void UPF_XDPProgram::ShareMaps(
    struct bpf_object* src_obj, struct bpf_object* dst_obj) {
  if (!src_obj || !dst_obj) return;
  struct bpf_map* dst_map;
  bpf_object__for_each_map(dst_map, dst_obj) {
    const char* name    = bpf_map__name(dst_map);
    struct bpf_map* src = bpf_object__find_map_by_name(src_obj, name);
    if (!src) continue;
    int fd = bpf_map__fd(src);
    if (fd < 0) continue;
    if (bpf_map__reuse_fd(dst_map, fd) != 0)
      Logger::upf_app().warn("ShareMaps: reuse_fd failed for '%s'", name);
  }
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::ShareMapsOwned(
    struct bpf_object* src, struct bpf_object* dst,
    const std::initializer_list<const char*>& owned_maps) {
  if (!src || !dst) return;
  for (const char* name : owned_maps) {
    struct bpf_map* src_map = bpf_object__find_map_by_name(src, name);
    if (!src_map) continue;
    int fd = bpf_map__fd(src_map);
    if (fd < 0) continue;
    struct bpf_map* dst_map = bpf_object__find_map_by_name(dst, name);
    if (!dst_map) continue;
    if (bpf_map__reuse_fd(dst_map, fd) != 0)
      Logger::upf_app().warn("ShareMapsOwned: reuse_fd failed for '%s'", name);
    else
      Logger::upf_app().debug("ShareMapsOwned: '%s' shared", name);
  }
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::PopulateProgramArray(const PipelineFeatureFlags& flags) {
  const bool is_eth = (flags.pdu_type == PduSessionType::Ethernet);

  if (!is_eth && sl_ip_)
    InsertProgramSlot(PROG_SESSION_LOOKUP_IP, sl_ip_->GetXdpProgram());
  if (is_eth && sl_eth_)
    InsertProgramSlot(PROG_SESSION_LOOKUP_ETH, sl_eth_->GetXdpProgram());

  InsertProgramSlot(PROG_PDR_MATCH, pdr_->GetXdpProgram());
  InsertProgramSlot(PROG_FAR_APPLY, far_->GetXdpProgram());

  if (qer_) InsertProgramSlot(PROG_QER_APPLY, qer_->GetXdpProgram());
  /* qer_tc_: TC-BPF -- not inserted into XDP tail-call array. */
  if (urr_) InsertProgramSlot(PROG_URR_APPLY, urr_->GetXdpProgram());
  if (bar_) InsertProgramSlot(PROG_BAR_APPLY, bar_->GetXdpProgram());
  if (mar_) InsertProgramSlot(PROG_MAR_APPLY, mar_->GetXdpProgram());

  Logger::upf_app().info("UPF_XDPProgram: PopulateProgramArray complete");
}

//------------------------------------------------------------------------------
bool UPF_XDPProgram::InsertProgramSlot(
    uint32_t index, struct bpf_program* prog) {
  if (!prog || !tail_call_progs_map_) return false;
  int fd = bpf_program__fd(prog);
  if (fd < 0) return false;
  if (tail_call_progs_map_->Update(index, fd, BPF_ANY) != 0) {
    Logger::upf_app().error("InsertProgramSlot: failed for slot %u", index);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
std::vector<ProgramLoadInfo> UPF_XDPProgram::BuildPipelineLoadInfo(
    const PipelineFeatureFlags& flags) const {
  const bool is_eth = (flags.pdu_type == PduSessionType::Ethernet);
  std::vector<ProgramLoadInfo> info;

  // Map counts: ground truth from kernel .c source analysis.
  // Each count reflects only the maps actually referenced via BPF helpers
  // (bpf_map_lookup_elem, bpf_map_update_elem, bpf_redirect_map, etc.)
  // in the corresponding xdp_*_kern.c file.
  if (!is_eth) {
    info.push_back({"N3EntryProgram", 3, gtp_interface_, false, false});
    info.push_back({"SessionLookupIPProgram", 5, "", false, false});
  } else {
    info.push_back({"N3EthEntryProgram", 3, gtp_interface_, false, false});
    info.push_back({"SessionLookupETHProgram", 6, "", false, false});
  }
  info.push_back({"PdrMatchProgram", 5, "", false, false});
  info.push_back({"FARProgram", 8, "", false, false});
  if (qer_) {
    info.push_back({"QERProgram", 3, "", false, false});
    info.push_back({"QERTCProgram", 1, "", true, true});
  }
  if (urr_) info.push_back({"URRProgram", 5, "", false, false});
  if (bar_) info.push_back({"BARProgram", 5, "", false, false});
  if (mar_) info.push_back({"MARProgram", 5, "", false, false});
  if (!is_eth)
    info.push_back({"N6EntryProgram", 3, non_gtp_interface_, false, false});
  else
    info.push_back({"N6EthEntryProgram", 4, non_gtp_interface_, false, false});

  return info;
}
//------------------------------------------------------------------------------
void UPF_XDPProgram::TearDown() {
  /* Tear down stage programs first -- no interface attachments */
  mar_    = nullptr;
  bar_    = nullptr;
  urr_    = nullptr;
  qer_    = nullptr;
  qer_tc_ = nullptr;
  far_    = nullptr;
  pdr_    = nullptr;
  sl_eth_ = nullptr;
  sl_ip_  = nullptr;

  /* Tear down entry programs -- lifecycle_ destructor calls tearDown() */
  n6_eth_ = nullptr;
  n3_eth_ = nullptr; /* ETH primary -- destroy after secondary */
  n6_     = nullptr;
  n3_     = nullptr; /* IP primary  -- destroy after secondary */

  Logger::upf_app().info("UPF_XDPProgram: TearDown complete");
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::InitializeMaps(struct bpf_object_skeleton* primary_skel) {
  /*
   * Wrap the 4 maps that every primary entry program owns.
   * Both xdp_n3_entry_kern.c and xdp_n3_eth_entry_kern.c include:
   *   tail_call_dispatcher.h -> tail_call_progs_map, packet_context_map,
   *                             session_rules_enabled_map
   *   stats_maps.h           -> mc_stats_map
   */
  maps_    = std::make_shared<BPFMaps>(primary_skel);
  auto get = [&](const char* name) {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };
  tail_call_progs_map_ = get("tail_call_progs_map");
  packet_ctx_map_      = get("packet_context_map");
  session_rules_map_   = get("session_rules_enabled_map");
  mc_stats_map_        = get("mc_stats_map");

  Logger::upf_app().info("UPF_XDPProgram: Map initialization completed");
}

/* Section: Interface configuration */

//------------------------------------------------------------------------------
void UPF_XDPProgram::CreateUpfInterfaceMapEntry(reference_point_t s) {
  if (!upf_iface_map_) {
    Logger::upf_app().error(
        "CreateUpfInterfaceMapEntry: upf_iface_map_ not initialized");
    return;
  }

  /* Log map capacity so we can catch E2BIG before it happens */
  {
    struct bpf_map* raw_map =
        bpf_object__find_map_by_name(far_->GetBpfObject(), "upf_interface_map");
    if (raw_map) {
      Logger::upf_app().debug(
          "CreateUpfInterfaceMapEntry: key=%u  map_fd=%d  max_entries=%u", s,
          bpf_map__fd(raw_map), bpf_map__max_entries(raw_map));
    }
  }

  auto m = upf_iface_map_;
  struct interface_config iface;
  __builtin_memset(&iface, 0, sizeof(iface));

  /* Helper: convert network-order uint32_t to dotted-decimal string */
  auto ip_str = [](uint32_t addr) -> std::string {
    struct in_addr a;
    a.s_addr = addr;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
  };

  switch (s) {
    case N3_INTERFACE:
      iface.ipv4_address = upf::GetN3Ip();
      iface.port         = upf::GetN3Port();
      strncpy(iface.if_name, upf::GetN3Iface().c_str(), IF_NAME_MAX_LEN - 1);
      Logger::upf_app().debug(
          "  N3: ip=%s  port=%u  iface=%s", ip_str(iface.ipv4_address).c_str(),
          iface.port, iface.if_name);
      m->Update(s, iface, BPF_ANY);
      Logger::upf_app().debug("  N3: upf_interface_map updated OK");
      break;
    case N4_INTERFACE:
      iface.ipv4_address = upf::GetN4Ip();
      iface.port         = upf::GetN4Port();
      strncpy(iface.if_name, upf::GetN4Iface().c_str(), IF_NAME_MAX_LEN - 1);
      Logger::upf_app().debug(
          "  N4: ip=%s  port=%u  iface=%s", ip_str(iface.ipv4_address).c_str(),
          iface.port, iface.if_name);
      m->Update(s, iface, BPF_ANY);
      Logger::upf_app().debug("  N4: upf_interface_map updated OK");
      break;
    case N6_INTERFACE:
      iface.ipv4_address = upf::GetN6Ip();
      iface.port         = 0;
      strncpy(iface.if_name, upf::GetN6Iface().c_str(), IF_NAME_MAX_LEN - 1);
      Logger::upf_app().debug(
          "  N6: ip=%s  port=%u  iface=%s", ip_str(iface.ipv4_address).c_str(),
          iface.port, iface.if_name);
      m->Update(s, iface, BPF_ANY);

      Logger::upf_app().debug("  N6: upf_interface_map updated OK");
      break;
    default:
      Logger::upf_app().error(
          "CreateUpfInterfaceMapEntry: unknown reference point %d", s);
  }
}

/* Section: GetMapByName */

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetMapByName(const std::string& n) {
  /* Primary entry skeleton infrastructure maps */
  if (n == "tail_call_progs_map") return tail_call_progs_map_;
  if (n == "packet_context_map") return packet_ctx_map_;
  if (n == "session_rules_enabled_map") return session_rules_map_;
  if (n == "mc_stats_map") return mc_stats_map_;

  /* IP session maps -- SessionLookupIPProgram */
  if (n == "session_by_ue_ip_map")
    return sl_ip_ ? sl_ip_->GetSessionByUeIpMap() : nullptr;
  if (n == "pdrs_per_session_map")
    return sl_ip_ ? sl_ip_->GetSessionPdrsMap() : nullptr;
  if (n == "rules_match_pdr_map")
    return sl_ip_ ? sl_ip_->GetRulesMatchMap() : nullptr;
  if (n == "session_qos_enabled_map")
    return sl_ip_ ? sl_ip_->GetSessionQosEnabledMap() : nullptr;
  if (n == "m_framed_route_mapping")
    return sl_ip_ ? sl_ip_->GetFramedRouteMappingMap() : nullptr;
  if (n == "framed_routing_flag")
    return sl_ip_ ? sl_ip_->GetFramedRoutingFlagMap() : nullptr;
  if (n == "feature_dispatch_map")
    return sl_ip_ ? sl_ip_->GetFeatureDispatchMap() : nullptr;

  /* ETH session maps -- SessionLookupETHProgram */
  if (n == "session_by_mac_map")
    return sl_eth_ ? sl_eth_->GetSessionByMacMap() : nullptr;
  if (n == "mac_pdu_session_map")
    return sl_eth_ ? sl_eth_->GetMacPduSessionMap() : nullptr;
  if (n == "eth_session_mapping_map")
    return sl_eth_ ? sl_eth_->GetEthSessionMappingMap() : nullptr;
  if (n == "eth_session_pdrs_map")
    return sl_eth_ ? sl_eth_->GetEthSessionPdrsMap() : nullptr;
  if (n == "eth_rules_match_pdr_map")
    return sl_eth_ ? sl_eth_->GetEthRulesMatchPdrMap() : nullptr;
  if (n == "eth_egress_ifindex_map")
    return sl_eth_ ? sl_eth_->GetEthEgressIfindexMap() : nullptr;

  /* Interface maps -- upf_iface_map_ set in Setup() from FAR (IP) or
   * n6_eth_ (ETH) */
  if (n == "upf_interface_map") return upf_iface_map_;
  if (n == "redirect_interfaces_map")
    return far_ ? far_->GetRedirectInterfacesMap() : nullptr;
  if (n == "arp_table_map") return far_ ? far_->GetArpTableMap() : nullptr;

  /* PDR maps */
  if (n == "sdf_filters_map") return pdr_ ? pdr_->GetSdfFilterMap() : nullptr;

  /* URR maps */
  if (n == "urr_config_map") return urr_ ? urr_->GetUrrConfigMap() : nullptr;
  if (n == "urr_volume_counters_map")
    return urr_ ? urr_->GetUrrVolumeMap() : nullptr;

  /* BAR maps */
  if (n == "bar_config_map") return bar_ ? bar_->GetBarConfigMap() : nullptr;
  if (n == "bar_state_map") return bar_ ? bar_->GetBarStateMap() : nullptr;

  /* MAR maps */
  if (n == "mar_config_map") return mar_ ? mar_->GetMarConfigMap() : nullptr;
  if (n == "mar_access_state_map")
    return mar_ ? mar_->GetMarAccessStateMap() : nullptr;

  Logger::upf_app().warn("GetMapByName: '%s' not found", n.c_str());
  return nullptr;
}

/* Section: Framed routing */

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetFramedRouteMappingMap() {
  return sl_ip_ ? sl_ip_->GetFramedRouteMappingMap() : nullptr;
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::UpdateFramedRouteMappingMap(
    uint32_t ue_ip, FramedRoutingKeyBPF key) {
  auto m = GetFramedRouteMappingMap();
  if (m) {
    uint32_t k = hash_framed_routing_key(&key);
    m->Update(k, ue_ip, BPF_ANY);
  }
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::RemoveFramedRoute(FramedRoutingKeyBPF key) {
  auto m = GetFramedRouteMappingMap();
  if (m) {
    uint32_t k = hash_framed_routing_key(&key);
    uint32_t v;
    if (m->Lookup(k, &v) == 0) m->Remove(k);
  }
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::SetFramedRouting(bool enable) {
  auto m = sl_ip_ ? sl_ip_->GetFramedRoutingFlagMap() : nullptr;
  if (m) {
    uint8_t v = enable ? 1 : 0;
    uint8_t k = 0;
    m->Update(k, v, BPF_ANY);
  }
}

/* Section: RemoveProgramMap */

//------------------------------------------------------------------------------
void UPF_XDPProgram::RemoveProgramMap(uint32_t key) {
  if (tail_call_progs_map_) tail_call_progs_map_->Remove(key);
}

/* Section: Delegated map getters */

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> UPF_XDPProgram::GetMaps() {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSessionMappingMap() const {
  return sl_ip_ ? sl_ip_->GetSessionByUeIpMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSessionMacMap() const {
  return sl_eth_ ? sl_eth_->GetSessionByMacMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetRulesMatchPdrMap() const {
  return sl_ip_ ? sl_ip_->GetRulesMatchMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSessionPdrsMap() const {
  return sl_ip_ ? sl_ip_->GetSessionPdrsMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSdfFilterMap() const {
  return pdr_ ? pdr_->GetSdfFilterMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetQosEnablingMap() const {
  return sl_ip_ ? sl_ip_->GetSessionQosEnabledMap() : nullptr;
}
std::shared_ptr<BPFMap> UPF_XDPProgram::GetFeatureDispatchMap() const {
  return sl_ip_ ? sl_ip_->GetFeatureDispatchMap() : nullptr;
}

//------------------------------------------------------------------------------
size_t UPF_XDPProgram::GetTotalMapCount() const {
  size_t total = 0;
  /* Only non-null programs contribute -- exactly one entry pair is alive */
  if (n3_) total += n3_->GetMapCount();
  if (n6_) total += n6_->GetMapCount();
  if (n3_eth_) total += n3_eth_->GetMapCount();
  if (n6_eth_) total += n6_eth_->GetMapCount();
  if (sl_ip_) total += sl_ip_->GetMapCount();
  if (sl_eth_) total += sl_eth_->GetMapCount();
  if (pdr_) total += pdr_->GetMapCount();
  if (far_) total += far_->GetMapCount();
  if (qer_) total += qer_->GetMapCount();
  /* qer_tc_: TC-BPF -- no GetMapCount(). TC maps are per-session. */
  if (urr_) total += urr_->GetMapCount();
  if (bar_) total += bar_->GetMapCount();
  if (mar_) total += mar_->GetMapCount();
  return total;
}

//------------------------------------------------------------------------------
bool UPF_XDPProgram::IsNativeXdp(const std::string& iface) const {
  if (iface == gtp_interface_) {
    if (n3_) return n3_->GetLifeCycle()->IsNativeXdp(iface);
    if (n3_eth_) return n3_eth_->GetLifeCycle()->IsNativeXdp(iface);
  }
  if (iface == non_gtp_interface_) {
    if (n6_) return n6_->GetLifeCycle()->IsNativeXdp(iface);
    if (n6_eth_) return n6_eth_->GetLifeCycle()->IsNativeXdp(iface);
  }
  Logger::upf_app().warn("IsNativeXdp: unknown interface '%s'", iface.c_str());
  return false;
}

//------------------------------------------------------------------------------
std::string UPF_XDPProgram::GetXdpModeString(const std::string& iface) const {
  if (iface == gtp_interface_) {
    if (n3_) return n3_->GetLifeCycle()->GetXdpModeString(iface);
    if (n3_eth_) return n3_eth_->GetLifeCycle()->GetXdpModeString(iface);
  }
  if (iface == non_gtp_interface_) {
    if (n6_) return n6_->GetLifeCycle()->GetXdpModeString(iface);
    if (n6_eth_) return n6_eth_->GetLifeCycle()->GetXdpModeString(iface);
  }
  Logger::upf_app().warn(
      "GetXdpModeString: unknown interface '%s'", iface.c_str());
  return "Unknown";
}
