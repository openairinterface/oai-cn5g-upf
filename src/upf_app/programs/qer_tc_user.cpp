#include "qer_tc_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>  // bpf calls
//#include "../include/bpf/libbpf.h"  // bpf wrappers
#include <iostream>   // cout
#include <stdexcept>  // exception
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include <chrono>
#include <iostream>
#include "interfaces.h"
#include "logger.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc/htb.h>
#include <NetlinkManager.h>
#include "standardized_5qi.h"
#include "helpers/GetNicInformation.hpp"
#include "helpers/CmdRunner.hpp"
//#include "standardized_5qi_qos_mapping.h"
//#include "qer_maps.h"

#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>

#include <getopt.h>
#include <linux/in6.h>
#include <arpa/inet.h>
#include <linux/bpf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#ifndef HTB_SCHEDULER
#define HTB_SCHEDULER "htb"
#endif  // HTB_SCHEDULER

#ifndef UDP_INTERFACE
#define UDP_INTERFACE UserPlaneComponent::getInstance().getUDPInterface()
#endif  // UDP_INTERFACE

#ifndef GTP_INTERFACE
#define GTP_INTERFACE UserPlaneComponent::getInstance().getGTPInterface()
#endif  // GTP_INTERFACE

#ifndef DEFAULT_RATE
#define DEFAULT_RATE NicInformationGetter::retrieveRate(GTP_INTERFACE)
#ifndef MAX_RATE
#define MAX_RATE DEFAULT_RATE
#endif  // MAX_RATE
#endif  // DEFAULT_RATE

#ifndef DEFAULT_CEIL
#define DEFAULT_CEIL NicInformationGetter::retrieveCeil(GTP_INTERFACE)
#ifndef MAX_CEIL
#define MAX_CEIL DEFAULT_CEIL
#endif  // MAX_CEIL
#endif  // DEFAULT_CEIL

#ifndef DEFAULT_QFI
#define DEFAULT_QFI 5
#endif  // DEFAULT_QFI

#ifndef BUILD_DIRECTORY
#define BUILD_DIRECTORY                                                        \
  "build/upf/build/upf_app/bpf/CMakeFiles/qer_tc.dir/rules/qer"
#endif  // BUILD_DIRECTORY

static int verbose = 1;

#define EGRESS_HANDLE 0x1
#define EGRESS_PRIORITY 0xC02F

#define INGRESS_HANDLE 0x1
#define INGRESS_PRIORITY 0xC02F

/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::QERProgram() : BPFProgram() {
  mpLifeCycle = std::make_shared<QERProgramLifeCycle>(
      qer_tc_kernel_c__open, qer_tc_kernel_c__load, qer_tc_kernel_c__attach,
      qer_tc_kernel_c__destroy);
}

/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::~QERProgram() {}

/*---------------------------------------------------------------------------------------------------------------*/

struct qer_tc_kernel_c* QERProgram::get_bpf_skel_object() {
  struct qer_tc_kernel_c* obj; /* Skeleton gave us this */
  char buf[100];
  int err;

  /* Skeleton header file have BPF-object as inline code */
  obj = qer_tc_kernel_c__open();
  err = libbpf_get_error(obj);

  if (err) {
    libbpf_strerror(err, buf, sizeof(buf));
    fprintf(stderr, "Couldn't open BPF skeleton:(%d) %s\n", err, buf);
    return NULL;
  }

  /* Add code here that change BPF-obj config before loading */

  /* Loading BPF-code into kernel, verifier will check, but not attach */
  err = qer_tc_kernel_c__load(obj);

  if (err) {
    libbpf_strerror(err, buf, sizeof(buf));
    fprintf(stderr, "Couldn't load BPF skeleton:(%d) %s\n", err, buf);
    qer_tc_kernel_c__destroy(obj);
    return NULL;
  }

  return obj;
}

/*---------------------------------------------------------------------------------------------------------------*/

// int QERProgram::teardown_hook(int ifindex)
// {
// 	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
// 			    .attach_point = BPF_TC_EGRESS,
// 			    .ifindex = ifindex);
// 	int err;

// 	/* When destroying the hook, any and ALL attached TC-BPF (filter)
// 	 * programs are also detached.
// 	 */
// 	err = bpf_tc_hook_destroy(&hook);
// 	if (err)
// 		fprintf(stderr, "Couldn't remove clsact qdisc on %s\n", ifname);

// 	if (verbose)
// 		printf("Flushed all TC-BPF egress programs (via destroy
// hook)\n");

// 	return err;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// int QERProgram::tc_detach_egress(int ifindex)
// {
// 	int err;
// 	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
// 			    .attach_point = BPF_TC_EGRESS);
// 	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_info);

// 	opts_info.handle   = EGRESS_HANDLE;
// 	opts_info.priority = EGRESS_PRIORITY;

// 	/* Check what program we are removing */
// 	err = bpf_tc_query(&hook, &opts_info);
// 	if (err) {
// 		fprintf(stderr, "No egress program to detach "
// 			"for ifindex %d (err:%d)\n", ifindex, err);
// 		return err;
// 	}
// 	if (verbose)
// 		printf("Detaching TC-BPF prog id:%d\n", opts_info.prog_id);

// 	/* Attempt to detach program */
// 	opts_info.prog_fd = 0;
// 	opts_info.prog_id = 0;
// 	opts_info.flags = 0;
// 	err = bpf_tc_detach(&hook, &opts_info);
// 	if (err) {
// 		fprintf(stderr, "Cannot detach TC-BPF program id:%d "
// 			"for ifindex %d (err:%d)\n", opts_info.prog_id,
// 			ifindex, err);
// 	}

// 	return teardown_hook(ifindex);
// }

/*---------------------------------------------------------------------------------------------------------------*/

// int tc_attach_egress(int ifindex, struct qer_tc_kernel_c *obj)
// {
// 	int err = 0;
// 	int fd;
// 	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
// 	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_egress);

// 	/* Selecting BPF-prog here: */
// 	//fd = bpf_program__fd(obj->progs.queue_map_4);
// 	fd = bpf_program__fd(obj->progs.not_txq_zero);
// 	if (fd < 0) {
// 		fprintf(stderr, "Couldn't find egress program\n");
// 		err = -ENOENT;
// 		goto out;
// 	}
// 	attach_egress.prog_fd = fd;

// 	hook.ifindex = ifindex;

// 	err = bpf_tc_hook_create(&hook);
// 	if (err && err != -EEXIST) {
// 		fprintf(stderr, "Couldn't create TC-BPF hook for "
// 			"ifindex %d (err:%d)\n", ifindex, err);
// 		goto out;
// 	}
// 	if (verbose && err == -EEXIST) {
// 		printf("Success: TC-BPF hook already existed "
// 		       "(Ignore: \"libbpf: Kernel error message\")\n");
// 	}

// 	hook.attach_point = BPF_TC_EGRESS;
// 	attach_egress.flags    = BPF_TC_F_REPLACE;
// 	attach_egress.handle   = EGRESS_HANDLE;
// 	attach_egress.priority = EGRESS_PRIORITY;
// 	err = bpf_tc_attach(&hook, &attach_egress);
// 	if (err) {
// 		fprintf(stderr, "Couldn't attach egress program to "
// 			"ifindex %d (err:%d)\n", hook.ifindex, err);
// 		goto out;
// 	}

// 	if (verbose) {
// 		printf("Attached TC-BPF program id:%d\n",
// 		       attach_egress.prog_id);
// 	}
// out:
// 	return err;
// }

/*---------------------------------------------------------------------------------------------------------------*/

struct bpf_program* find_program_by_title(
    struct bpf_object* obj, const char* title) {
  struct bpf_program* prog;
  bpf_object__for_each_program(prog, obj) {
    const char* prog_title = bpf_program__section_name(prog);
    if (prog_title && !strcmp(prog_title, title)) {
      return prog;
    }
  }
  return NULL;
}

// struct bpf_program *
// bpf_object__find_program_by_title(const struct bpf_object *obj,
// 				  const char *title)
// {
// 	struct bpf_program *pos;

// 	bpf_object__for_each_program(pos, obj) {
// 		if (pos->sec_name && !strcmp(pos->sec_name, title))
// 			return pos;
// 	}
// 	return errno = ENOENT, NULL;
// }

int QERProgram::tc_attach_egress(
    int ifindex, struct qer_tc_kernel_c* bpf_obj, const char* section_name) {
  int err = 0;
  int fd;
  struct bpf_program* prog = NULL;
  DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
  DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_egress);

  hook.ifindex = ifindex;

  // Retrieve the BPF program based on the section name
  // prog = bpf_object__find_program_by_title(bpf_obj->obj, section_name);
  prog = find_program_by_title(bpf_obj->obj, section_name);
  if (!prog) {
    fprintf(
        stderr, "Couldn't find program with section name: %s\n", section_name);
    err = -ENOENT;
    goto out;
  }

  fd = bpf_program__fd(prog);
  if (fd < 0) {
    fprintf(
        stderr,
        "Couldn't get file descriptor for program with section name: %s\n",
        section_name);
    err = -ENOENT;
    goto out;
  }
  attach_egress.prog_fd = fd;

  // Create TC-BPF hook
  err = bpf_tc_hook_create(&hook);
  if (err && err != -EEXIST) {
    fprintf(
        stderr, "Couldn't create TC-BPF hook for ifindex %d (err:%d)\n",
        ifindex, err);
    goto out;
  }
  if (verbose && err == -EEXIST) {
    printf(
        "Success: TC-BPF hook already existed (Ignore: \"libbpf: Kernel error "
        "message\")\n");
  }

  // Attach the BPF program
  hook.attach_point      = BPF_TC_EGRESS;
  attach_egress.flags    = BPF_TC_F_REPLACE;
  attach_egress.handle   = EGRESS_HANDLE;
  attach_egress.priority = EGRESS_PRIORITY;
  err                    = bpf_tc_attach(&hook, &attach_egress);
  if (err) {
    fprintf(
        stderr, "Couldn't attach egress program to ifindex %d (err:%d)\n",
        hook.ifindex, err);
    goto out;
  }

  if (verbose) {
    printf(
        "Attached TC-BPF program id:%d with section name: %s\n",
        attach_egress.prog_id, section_name);
  }

out:
  return err;
}

/*---------------------------------------------------------------------------------------------------------------*/

int QERProgram::tc_attach_ingress(
    int ifindex, struct qer_tc_kernel_c* bpf_obj, const char* section_name) {
  int err = 0;
  int fd;
  struct bpf_program* prog = NULL;
  DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
  DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_ingress);

  hook.ifindex = ifindex;

  // Retrieve the BPF program based on the section name
  // prog = bpf_object__find_program_by_title(bpf_obj->obj, section_name);
  prog = find_program_by_title(bpf_obj->obj, section_name);

  if (!prog) {
    fprintf(
        stderr, "Couldn't find program with section name: %s\n", section_name);
    err = -ENOENT;
    goto out;
  }

  fd = bpf_program__fd(prog);
  if (fd < 0) {
    fprintf(
        stderr,
        "Couldn't get file descriptor for program with section name: %s\n",
        section_name);
    err = -ENOENT;
    goto out;
  }
  attach_ingress.prog_fd = fd;

  // Create TC-BPF hook
  err = bpf_tc_hook_create(&hook);
  if (err && err != -EEXIST) {
    fprintf(
        stderr, "Couldn't create TC-BPF hook for ifindex %d (err:%d)\n",
        ifindex, err);
    goto out;
  }
  if (verbose && err == -EEXIST) {
    printf(
        "Success: TC-BPF hook already existed (Ignore: \"libbpf: Kernel error "
        "message\")\n");
  }

  // Attach the BPF program
  hook.attach_point       = BPF_TC_INGRESS;
  attach_ingress.flags    = BPF_TC_F_REPLACE;
  attach_ingress.handle   = INGRESS_HANDLE;
  attach_ingress.priority = INGRESS_PRIORITY;
  err                     = bpf_tc_attach(&hook, &attach_ingress);
  if (err) {
    fprintf(
        stderr, "Couldn't attach ingress program to ifindex %d (err:%d)\n",
        hook.ifindex, err);
    goto out;
  }

  if (verbose) {
    printf(
        "Attached TC-BPF program id:%d with section name: %s\n",
        attach_ingress.prog_id, section_name);
  }

out:
  return err;
}

/*---------------------------------------------------------------------------------------------------------------*/

// Function to add the clsact qdisc to an interface
int QERProgram::add_clsact_qdisc(
    int ifindex, enum bpf_tc_attach_point attach_point) {
  int err = 0;
  DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = attach_point);

  // Set the interface index in the hook options
  hook.ifindex = ifindex;

  // Create the clsact qdisc
  err = bpf_tc_hook_create(&hook);
  if (err && err != -EEXIST) {
    fprintf(
        stderr, "Failed to add clsact qdisc on interface %d (err:%d)\n",
        ifindex, err);
    return err;
  }

  if (verbose && err == -EEXIST) {
    printf("clsact qdisc already exists on interface %d\n", ifindex);
  }

  return 0;
}

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::storeQosFlow(std::shared_ptr<pfcp::pfcp_qer> pQer) {
  struct s_fiveQosFlow fiveFlow;
  memset(&fiveFlow, 0, sizeof(struct s_fiveQosFlow));

  fiveFlow.gate.dl_gate = pQer->gate_status.second.dl_gate;
  fiveFlow.gate.ul_gate = pQer->gate_status.second.ul_gate;

  fiveFlow.gbr.dl_gbr = pQer->gbr.second.dl_gbr;
  fiveFlow.gbr.ul_gbr = pQer->gbr.second.ul_gbr;

  fiveFlow.mbr.dl_mbr = pQer->mbr.second.dl_mbr;
  fiveFlow.mbr.ul_mbr = pQer->mbr.second.ul_mbr;

  fiveFlow.qfi = pQer->qfi.second.qfi;

  qosFlowsQfis.push_back(fiveFlow);

  uint32_t qer_id = pQer->qer_id.second.qer_id;

  getQoSFlowMap()->update(qer_id, fiveFlow, BPF_ANY);
}

/*---------------------------------------------------------------------------------------------------------------*/
// // Method definition to initialize class_params
// void QERProgram::setPduSessionClassAttributes(
//     const char* qdiscScheduler, std::string interface) {
//   NicInformationGetter nicConfiguration;
//   // Initialize classAtt members
//   pduSessionClassAtt            = new classParams();
//   pduSessionClassAtt->scheduler = qdiscScheduler;
//   pduSessionClassAtt->rate      =
//   NicInformationGetter::retrieveRate(interface); pduSessionClassAtt->ceil =
//   NicInformationGetter::retrieveCeil(interface); pduSessionClassAtt->burst =
//   NicInformationGetter::retrieveBurst(interface); pduSessionClassAtt->cburst
//   = NicInformationGetter::retrieveCBurst(interface);
//   pduSessionClassAtt->priority  = -1;

//   Logger::upf_app().debug(
//       "QDISC Root Rate (GBR) : %d", pduSessionClassAtt->rate);
//   Logger::upf_app().debug(
//       "QDISC Root Ceil (MBR) : %d", pduSessionClassAtt->ceil);
//   Logger::upf_app().debug(
//       "QDISC Root Burst      : %d", pduSessionClassAtt->burst);
//   Logger::upf_app().debug(
//       "QDISC Root CBurst     : %d", pduSessionClassAtt->cburst);
//   Logger::upf_app().debug(
//       "QDISC Root Priority   : %d", pduSessionClassAtt->priority);
// }

/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize class_params
// void QERProgram::setQosFlowsClassesAttributes() {
//   for (int i = 0; i < savedQers.size() && i < qosFlowsQfis.size(); ++i) {
//     const auto& qer              = savedQers[i];
//     struct classParams* classAtt = new classParams();

//     classAtt->scheduler = pduSessionClassAtt->scheduler;
//     if (qosFlowsQfis[i].qfi != DEFAULT_QFI) {
//       classAtt->rate     = qosFlowsQfis[i].gbr.dl_gbr;
//       classAtt->ceil     = qosFlowsQfis[i].mbr.dl_mbr;
//       classAtt->burst    = 0;
//       classAtt->cburst   = 0;
//       classAtt->priority = -1;
//     } else {
//       classAtt->rate     = 100;
//       classAtt->ceil     = 200;
//       classAtt->burst    = 0;
//       classAtt->cburst   = 0;
//       classAtt->priority = -1;
//     }

//     qosFlowsClassesAtt.push_back(classAtt);

//     Logger::upf_app().debug(
//         "    HTB Class ID (QER) ........... %d",
//         savedQers[i]->qer_id.second.qer_id);
//     Logger::upf_app().debug("         Class QFI:      %d",
//     qosFlowsQfis[i].qfi); Logger::upf_app().debug("         Class Rate:
//     %dkbps", classAtt->rate); Logger::upf_app().debug("         Class Ceil:
//     %dkbps", classAtt->ceil); Logger::upf_app().debug("         Class Burst:
//     %d", classAtt->burst); Logger::upf_app().debug("         Class CBurst:
//     %d", classAtt->cburst); Logger::upf_app().debug("         Class Priority:
//     %d", classAtt->priority);
//   }
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Method definition to set pduSession class position
// void QERProgram::setPduSessionClassPosition(uint64_t seid) {
//   pduSessionClassPos            = new classPosition();
//   pduSessionClassPos->parentMaj = 1;
//   pduSessionClassPos->parentMin = 0;
//   pduSessionClassPos->childMaj  = 1;
//   pduSessionClassPos->childMin  = seid;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Method definition to set pduSession class position
// void QERProgram::setQosFlowsClassesPositions() {
//   for (int i = 0; i < qosFlowsQfis.size(); i++) {
//     struct classPosition* classPos = new classPosition();

//     classPos->parentMaj = pduSessionClassPos->parentMaj;
//     classPos->parentMin = pduSessionClassPos->parentMin;
//     classPos->childMaj  = pduSessionClassPos->childMin;
//     classPos->childMin  = qosFlowsQfis[i].qfi;

//     qosFlowsClassesPos.push_back(classPos);

//     Logger::upf_app().debug(
//         "QDISC Root Position: %d:%d", classPos->parentMaj,
//         classPos->parentMin);
//     Logger::upf_app().debug(
//         "QDISC Root-Child Position: %d:%d", classPos->childMaj,
//         classPos->childMin);
//     Logger::upf_app().debug(
//         "HTB Class Position  %d:%d", classPos->childMaj, classPos->childMin);
//   }
// }

/*---------------------------------------------------------------------------------------------------------------*/

bool QERProgram::no_htb_root_qdisc(std::string interface) {
  std::string cmd = {};
  uint32_t ret    = 0;

  cmd = fmt::format(
      "tc qdisc show dev {} | awk '/htb/ {{found=1; print 1}} END {{if "
      "(!found) print 0}}'",
      interface);
  ret = std::stoi(CmdRunner::exec(cmd).c_str());
  return ret ? false : true;
}

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup(
    uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer) {
  QdiscHelper qdiscHelper;
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  struct qer_tc_kernel_c* obj = NULL;

  // savedQers = pQer;

  std::string cmd = {};
  int rc          = 0;
  int if_index    = 0;

  uint32_t udpInterfaceIndex = if_nametoindex(UDP_INTERFACE.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(GTP_INTERFACE.c_str());
  uint32_t uplinkId          = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlinkId        = static_cast<uint32_t>(FlowDirection::DOWNLINK);
  mpEgressIfindexMap->update(uplinkId, udpInterfaceIndex, BPF_ANY);
  mpEgressIfindexMap->update(downlinkId, gtpInterfaceIndex, BPF_ANY);

  if (no_htb_root_qdisc(GTP_INTERFACE)) {
    Logger::upf_app().info(
        "Creating Root qdisc on interface %s", GTP_INTERFACE.c_str());
    cmd = fmt::format(
        "tc qdisc add dev {} root handle 1:0 htb default {}", GTP_INTERFACE,
        DEFAULT_QFI);
    rc = system((const char*) cmd.c_str());
  }

  Logger::upf_app().info("Create PDU Session Class 1:%d", seid);
  cmd = fmt::format(
      "tc class add dev {} parent 1:0 classid 1:{} htb rate {}kbit",
      GTP_INTERFACE, seid, MAX_RATE);
  rc = system((const char*) cmd.c_str());

  Logger::upf_app().debug("QDISC Root Rate (GBR) : %dkbps", MAX_RATE);
  Logger::upf_app().debug("QDISC Root Ceil (MBR) : %dkbps", MAX_CEIL);

  for (const auto& qer : pQer) {
    if (qer == nullptr) {
      continue;
    }

    uint8_t qfi      = qer->qfi.second.qfi;
    uint32_t qer_id  = qer->qer_id.second.qer_id;
    uint64_t dl_rate = DEFAULT_RATE;
    uint64_t dl_ceil = DEFAULT_CEIL;
    uint64_t ul_rate = DEFAULT_RATE;
    uint64_t ul_ceil = DEFAULT_CEIL;
    uint8_t dl_gate  = 0;
    uint8_t ul_gate  = 0;

    if (qfi != DEFAULT_QFI) {
      if (qer->gbr.second.dl_gbr != 0) dl_rate = qer->gbr.second.dl_gbr;

      if (qer->gbr.second.ul_gbr != 0) ul_rate = qer->gbr.second.ul_gbr;

      if (qer->mbr.second.dl_mbr != 0) dl_ceil = qer->mbr.second.dl_mbr;

      if (qer->mbr.second.ul_mbr != 0) ul_ceil = qer->mbr.second.ul_mbr;

      dl_gate = qer->gate_status.second.dl_gate;
      ul_gate = qer->gate_status.second.ul_gate;
    }

    struct s_fiveQosFlow fiveFlow;
    memset(&fiveFlow, 0, sizeof(struct s_fiveQosFlow));

    fiveFlow.gate.dl_gate = dl_gate;
    fiveFlow.gate.ul_gate = ul_gate;
    fiveFlow.gbr.dl_gbr   = dl_rate;
    fiveFlow.gbr.ul_gbr   = ul_rate;
    fiveFlow.mbr.dl_mbr   = dl_ceil;
    fiveFlow.mbr.ul_mbr   = ul_ceil;

    fiveFlow.qfi = qfi;
    getQoSFlowMap()->update(qer_id, fiveFlow, BPF_ANY);

    uint16_t minor = (ntohs(seid) * 256) + (qfi * 251 % 256);
    cmd            = fmt::format(
        "tc class add dev {} parent 1:{} classid {}:{} htb rate {}kbit ceil "
        "{}kbit",
        GTP_INTERFACE, seid, seid, minor, dl_rate, dl_ceil);
    rc = system((const char*) cmd.c_str());

    Logger::upf_app().debug("    HTB Class ID (QER) ........... %d", qer_id);
    Logger::upf_app().debug("         Class QFI:      %d", qfi);
    Logger::upf_app().debug("         Class Rate:     %dkbps", dl_rate);
    Logger::upf_app().debug("         Class Ceil:     %dkbps", dl_ceil);
  }

  Logger::upf_app().error(" =====================================0");
  cmd = fmt::format("tc qdisc add dev {} clsact", GTP_INTERFACE);
  rc  = system((const char*) cmd.c_str());
  Logger::upf_app().error(" =====================================1");

  Logger::upf_app().error("Attach Sesction tc_filter to gtp interface");
  // obj = get_bpf_skel_object();

  // if (obj == NULL)
  // 		rc = EXIT_FAILURE;

  // rc = tc_attach_egress(gtpInterfaceIndex, obj, "cls_filter");
  // if (rc)
  // 		rc = EXIT_FAILURE;

  mpLifeCycle->tcAttachEgress("tc_filter", mGTPInterface.c_str());

  Logger::upf_app().error(" =====================================00");
  cmd = fmt::format("tc qdisc add dev {} clsact", UDP_INTERFACE);
  rc  = system((const char*) cmd.c_str());
  Logger::upf_app().error(" =====================================11");

  // Logger::upf_app().error("Attach Sesction tc_redirect to udp interface");
  // rc = tc_attach_ingress(udpInterfaceIndex, obj, "tc_redirect");
  // if (rc)
  // 		rc = EXIT_FAILURE;

  mpLifeCycle->tcAttachIngress("tc_redirect", mUDPInterface.c_str());

  // cmd = fmt::format(
  //     "tc filter add dev {} egress bpf object-file "
  //     "/sys/fs/bpf/qer_tc_kernel section classifier/cls_filter",
  //     GTP_INTERFACE);
  // rc = system((const char*) cmd.c_str());

  Logger::upf_app().error(" =====================================2");
  cmd = fmt::format("tc qdisc add dev {} clsact", UDP_INTERFACE);
  rc  = system((const char*) cmd.c_str());

  // Logger::upf_app().error(" =====================================3");
  //   cmd = fmt::format(
  //       "tc filter add dev {} ingress bpf object-file
  //       /sys/fs/bpf/qer_tc_kernel section " "classifier/tc_redirect",
  //       UDP_INTERFACE);
  //   rc = system((const char*) cmd.c_str());

  Logger::upf_app().error(" =====================================4");
  // for (int i = 0; i < qosFlowsClassesAtt.size(); i++) {
  //   cmd = fmt::format(
  //       "tc class add dev {} parent 1:{} classid {}:{} htb rate {} ceil {}",
  //       gtpInterface, seid, seid, qosFlowsClassesPos[i]->childMin,
  //       qosFlowsClassesAtt[i]->rate, qosFlowsClassesAtt[i]->ceil);
  //   rc = system((const char*) cmd.c_str());
  // }
  // cmd = fmt::format("tc qdisc add dev {} clsact", gtpInterface);
  // rc  = system((const char*) cmd.c_str());

  // cmd = fmt::format(
  //     "tc filter add dev {} ingress parent 1:0 bpf obj "
  //     "/sys/fs/bpf/qer_tc_kernel sec classifier/cls_filter",
  //     gtpInterface);
  // rc = system((const char*) cmd.c_str());

  // cmd = fmt::format("tc qdisc add dev {} clsact", udpInterface);
  // rc  = system((const char*) cmd.c_str());

  // cmd = fmt::format(
  //     "tc filter add dev {} egress bpf obj /sys/fs/bpf/qer_udp_tc_kernel sec
  //     " "classifier/tc_redirect", udpInterface);
  // rc = system((const char*) cmd.c_str());
}

// change:
//  sudo tc class change dev br0 parent 1:1 classid 1:10 htb rate 1kbit ceil
//  5kbit burst 16b

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup() {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();
  // insertValuesIntoMaps();
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMaps> QERProgram::getMaps() {
  return mpMaps;
}

/*---------------------------------------------------------------------------------------------------------------*/
// TODO: Check when kill when running.
// It was noted the infinity loop.
void QERProgram::tearDown() {
  mpLifeCycle->tearDown();
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> QERProgram::geGtpUTunnelMap() const {
  return mpGtpUTunnelMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
// std::shared_ptr<BPFMap> QERProgram::getFilterMap() const {
//   return mpFilterMap;
// }

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> QERProgram::get5GQoSFlowParamsMap() const {
  return mp5GQoSFlowParamsMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> QERProgram::getQoSFlowMap() const {
  return mpQoSFlowMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> QERProgram::getEgressIfindexMap() const {
  return mpEgressIfindexMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> QERProgram::getSdfFilterMap() const {
  return mpSdfFilterMap;
}
/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpGtpUTunnelMap = std::make_shared<BPFMap>(mpMaps->getMap("m_gtp_u_tunnel"));
  // mpFilterMap     = std::make_shared<BPFMap>(mpMaps->getMap("m_filter"));
  mp5GQoSFlowParamsMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_5g_qos_flow_parameters"));
  mpQoSFlowMap   = std::make_shared<BPFMap>(mpMaps->getMap("m_qos_flow"));
  mpSdfFilterMap = std::make_shared<BPFMap>(mpMaps->getMap("m_sdf_filter"));
  mpEgressIfindexMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_egress_ifindex"));
}
