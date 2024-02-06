#include "qer_ebpf_tc_prgrm_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>     // bpf calls
#include <bpf/libbpf.h>  // bpf wrappers
#include <iostream>      // cout
#include <stdexcept>     // exception
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces.h"
#include "logger.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc/htb.h>




/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::QERProgram(
    const std::string& gtpInterface, const std::string& udpInterface)
    : mGTPInterface(gtpInterface), mUDPInterface(udpInterface) {
  mpLifeCycle = std::make_shared<QERProgramLifeCycle>(
      qer_ebpf_tc_prgrm_kernel_c__open,
      qer_ebpf_tc_prgrm_kernel_c__load,
      qer_ebpf_tc_prgrm_kernel_c__attach,
      qer_ebpf_tc_prgrm_kernel_c__destroy);
}

/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::~QERProgram() {}

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup() {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();
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
std::shared_ptr<BPFMap> QERProgram::getFilterMap() const {
  return mpFilterMap;
}

/*---------------------------------------------------------------------------------------------------------------*/

void QERProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpGtpUTunnelMap = std::make_shared<BPFMap>(mpMaps->getMap("m_gtp_u_tunnel"));
  mpFilterMap     = std::make_shared<BPFMap>(mpMaps->getMap("m_filter"));
}

/*---------------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------------*/

struct nl_sock *create_socket(){
    // Initialize Netlink socket
    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) {
        perror("nl_socket_alloc");
        exit(EXIT_FAILURE);
    }

    // Connect to Netlink socket
    if (nl_connect(sock, NETLINK_ROUTE) < 0) {
        perror("nl_connect");
        nl_socket_free(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}


/*---------------------------------------------------------------------------------------------------------------*/



/*---------------------------------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------------------------------------------*/

   
/*---------------------------------------------------------------------------------------------------------------*/    

struct rtnl_tc *allocate_tc(struct rtnl_tc *tc, struct nl_sock *sock, struct rtnl_qdisc *qdisc){
    // Allocate a new Traffic Control object
    tc = rtnl_tc_alloc();

    if (!tc) {
        perror("rtnl_tc_alloc");
        rtnl_qdisc_delete(sock, qdisc);
        nl_close(sock);
        nl_socket_free(sock);
        exit(EXIT_FAILURE);
    }

    return tc;
}

/*---------------------------------------------------------------------------------------------------------------*/
void add_qdisc_to_interface(const char *interface, struct nl_sock *sock, struct rtnl_qdisc *qdisc, struct rtnl_tc *tc){
    // Add the Qdisc to the interface (replace "eth0" with your interface name)
    if (rtnl_tc_add(sock, tc, NLM_F_CREATE | NLM_F_EXCL, RTM_NEWQDISC, 0, interface) < 0) {
        perror("rtnl_tc_add");
        rtnl_tc_free(tc);
        rtnl_qdisc_delete(sock, qdisc);
        nl_close(sock);
        nl_socket_free(sock);
        exit(EXIT_FAILURE);
    }
}

// /*---------------------------------------------------------------------------------------------------------------*/

// // Function to create and configure a Qdisc hierarchy
// void qer_tc::create_configure_hierarchy(struct rtnl_qdisc *root_qdisc, struct nl_sock *sock, qdisc_pdu_to_create, qdisc_qos_flows_to_create) {
    
//     // Create and configure parent classes and their children as needed
//     struct rtnl_qdisc *parent1 = create_parent_class(sock, seid);
//     struct rtnl_qdisc *child1 = create_child_class(sock, parent1, qfi[i]);
//     struct rtnl_qdisc *child2 = create_child_class(sock, parent1, qfi[j]);

//     // Attach parent Qdisc to root Qdisc
//     if (rtnl_qdisc_set_parent(parent1, root_qdisc) < 0) {
//         perror("rtnl_qdisc_set_parent");
//         exit(EXIT_FAILURE);
//     }
// }
// /*---------------------------------------------------------------------------------------------------------------*/
// // Function to create and configure the Qdisc hierarchy
// void qer_tc::create_configure_hierarchy(struct nl_sock *sock, const char *interface, std::vector<std::vector<uint32_t>> child_ids) {
//     // Create and configure parent classes
//     for (size_t i = 0; i < child_ids.size(); ++i) {
//         struct rtnl_qdisc *parent = create_parent_class(sock, interface, i + 1);
//         parent_qdiscs.push_back(parent);

//         // Create and attach child classes
//         std::vector<struct rtnl_qdisc *> children;
//         for (size_t j = 0; j < child_ids[i].size(); ++j) {
//             struct rtnl_qdisc *child = create_child_class(sock, parent, child_ids[i][j]);
//             children.push_back(child);
//         }
//         child_qdiscs.push_back(children);

//         // Attach parent Qdisc to root Qdisc
//         if (rtnl_qdisc_set_parent(parent, root_qdisc) < 0) {
//             perror("rtnl_qdisc_set_parent");
//             exit(EXIT_FAILURE);
//         }
//     }
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Function to create a parent class
// struct rtnl_qdisc *qer_tc::create_parent_class(struct nl_sock *sock, const char *interface, uint32_t parent_id) {
//     // Create parent Qdisc
//     struct rtnl_qdisc *parent_qdisc = rtnl_qdisc_alloc();
//     if (!parent_qdisc) {
//         perror("rtnl_qdisc_alloc");
//         exit(EXIT_FAILURE);
//     }
//     // Configure parent Qdisc as needed
//     rtnl_htb_set_rate(parent_qdisc, rate);

//     // Add parent Qdisc to the interface
//     if (rtnl_tc_add(sock, parent_qdisc, NLM_F_CREATE | NLM_F_REPLACE, RTM_NEWQDISC, 0, interface) < 0) {
//         perror("rtnl_tc_add");
//         rtnl_qdisc_free(parent_qdisc);
//         exit(EXIT_FAILURE);
//     }

//     return parent_qdisc;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Function to create a child class
// struct rtnl_qdisc *qer_tc::create_child_class(struct nl_sock *sock, struct rtnl_qdisc *parent, uint32_t child_id) {
//     // Create child Qdisc
//     struct rtnl_qdisc *child_qdisc = rtnl_qdisc_alloc();

//     if (!child_qdisc) {
//         perror("rtnl_qdisc_alloc");
//         exit(EXIT_FAILURE);
//     }
//     // Configure child Qdisc as needed
//     rtnl_htb_set_rate(child_qdisc, rate);

//     // Add child Qdisc to the parent
//     if (rtnl_qdisc_set_parent(child_qdisc, parent) < 0)  {
//         perror("rtnl_qdisc_set_parent");
//         rtnl_qdisc_free(child_qdisc);
//         exit(EXIT_FAILURE);
//     }

//     return child_qdisc;
// }










// #include "qer_tc.hpp"
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <netlink/route/link.h>

// // Constructor
// qer_tc::qer_tc(const char *kind, uint32_t rate) {
//     params.kind = kind;
//     params.rate = rate;
//     // Initialize other parameters as needed
// }
