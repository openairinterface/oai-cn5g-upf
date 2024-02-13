#include "QdiscHelpers.hpp"

#include <netlink/netlink.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc/htb.h>


#ifndef HTB_SCHEDULER
#define HTB_SCHEDULER "HTB"
#endif

/*---------------------------------------------------------------------------------------------------------------*/

QdiscHelper::QdiscHelper() {}


 /*---------------------------------------------------------------------------------------------------------------*/
// Method to create the socket
struct nl_sock *QdiscHelper::create_socket(){
    int err;
    struct nl_sock *socket;

    Logger::upf_app().info("Create a Netlink Socket");
    if (!(socket = nl_socket_alloc())){
        Logger::upf_app().error("nl_socket_alloc: Unable to allocate netlink socket");
        return nullptr;
    }

    // Connect to the socket
    if ((err = nl_connect(socket, NETLINK_ROUTE)) < 0) {
        Logger::upf_app().error("nl_connect:Unable to connect to the netlink socket");
        nl_socket_free(socket);
        return nullptr;
    }

    return socket;
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method to create a new HTB qdisc
struct rtnl_qdisc *QdiscHelper::create_qdisc(struct nl_sock *socket){
    struct rtnl_qdisc *qdisc;  
    Logger::upf_app().info("Create a Qdisc Object");
    
    if (!(qdisc = rtnl_qdisc_alloc())){
        Logger::upf_app().error("rtnl_qdisc_alloc: Unable to allocate a new qdisc");
        nl_close(socket);
        nl_socket_free(socket);
        return nullptr;
    }

    return qdisc;
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method to create a link cache object
struct nl_cache *QdiscHelper::create_link_cache(struct nl_sock *socket){
    int err;
    struct nl_cache *link_cache;
    
    Logger::upf_app().info("Create a Netlink Link Cache object");
    
    if ((err = rtnl_link_alloc_cache(socket, AF_UNSPEC, &link_cache)) < 0) {
        Logger::upf_app().error("Unable to allocate link cache: %s\n", nl_geterror(err));
        nl_socket_free(socket);
        return nullptr;
    } 

    return link_cache; 
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method to create a link object
struct rtnl_link *QdiscHelper::create_link(const char *iface, struct nl_cache *link_cache, struct nl_sock *socket){
  
  struct rtnl_link *link;
  Logger::upf_app().info("Create a Netlink Link object");
  
  if (!(link = rtnl_link_get_by_name(link_cache, iface))) {
    Logger::upf_app().error("rtnl_link_get_by_name: Interface %s not found\n", iface);
    nl_socket_free(socket);
    return nullptr;
  }

  return link;
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method to create a qdisc class object
struct rtnl_class *QdiscHelper::create_class(struct nl_sock *socket){      
    int err;
    struct rtnl_class *qdisc_class;  

    Logger::upf_app().info("Create a Qdisc Class");

    if (!(qdisc_class = rtnl_class_alloc())){
        Logger::upf_app().error("Unable to Allocate Qdisc Class Object");
        nl_socket_free(socket);
        return nullptr;
    }

    return qdisc_class;
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method to configure the root qdisc object
int QdiscHelper::configure_root_qdisc(struct nl_sock *socket, 
    struct rtnl_link *link,
    struct rtnl_qdisc *qdisc,
    struct qdisc_root_params qdisc_att
    // const char *qdisc_scheduler, 
    // uint32_t defaultClass
    )
{    
  int err;
  Logger::upf_app().info("Set the Root Qdisc Attributes");
  //rtnl_tc_set_ifindex(TC_CAST(qdisc), master_index);
  rtnl_tc_set_link(TC_CAST(qdisc), link);
  rtnl_tc_set_parent(TC_CAST(qdisc), TC_H_ROOT);

  Logger::upf_app().info("Delete Existing Qdisc");
  rtnl_qdisc_delete(socket, qdisc);
  //rtnl_qdisc_put(qdisc);
    

  rtnl_tc_set_handle(TC_CAST(qdisc), TC_HANDLE(1,0));
  if ((err = rtnl_tc_set_kind(TC_CAST(qdisc), qdisc_att->scheduler))) {
    Logger::upf_app().error("rtnl_tc_set_kind: Cannot allocate :%s\n", qdisc_att->scheduler);
    return(err);
  }
  
  Logger::upf_app().info("Set Default Class for Unclassified Traffic");
  rtnl_htb_set_defcls(qdisc, TC_HANDLE(1, qdisc_att->defaultClass));
  rtnl_htb_set_rate2quantum(qdisc, qdisc_att->quantum);
  
  /* Submit request to kernel and wait for response */
  Logger::upf_app().info("Submit Qdisc Creation Request to Kernel and Wait for Response");
  if ((err = rtnl_qdisc_add(socket, qdisc, NLM_F_CREATE))) {
    Logger::upf_app().error("rtnl_qdisc_add: Can not allocate Qdisc\n");
    return(err);
  }
  
  /* Return the qdisc object to free memory resources */
  rtnl_qdisc_put(qdisc);
  return 0;
}


/*---------------------------------------------------------------------------------------------------------------*/
/* Method to configure the Root Qdisc Class object*/
int QdiscHelper::configure_root_class(struct nl_sock *socket,
    struct rtnl_link *link,
    struct rtnl_class *qdisc_class,
    class_params *class_att
    // const char *qdisc_scheduler, 
    // uint32_t rate,
    // uint32_t ceil
    ){
  int err;

  Logger::upf_app().info("Set Root Class Attributes:");
  rtnl_tc_set_link(TC_CAST(qdisc_class), link);
  rtnl_tc_set_parent(TC_CAST(qdisc_class), TC_H_ROOT);
  rtnl_tc_set_handle(TC_CAST(qdisc_class), 1);
  
  if ((err = rtnl_tc_set_kind(TC_CAST(qdisc_class), class_att->scheduler))) {
      Logger::upf_app().error("Unable to set Scheduler %s to Class", class_att->scheduler);
      return(err);
  }

  if (strcmp(rtnl_tc_get_kind(TC_CAST(qdisc_class)), HTB_SCHEDULER) == 0){
	/*
      TODO: - Do we need to divide by 8 ?
            - rate = rate/8; 
            - ceil = ceil/8; 
    */
    if (rate > 0) {
        rtnl_htb_set_rate(qdisc_class, class_att->rate);
    }

    if (rate > 0) {        
	    rtnl_htb_set_ceil(qdisc_class, class_att->ceil);
    }
  
    /*
    TODO: - Check if we need burst and cburst values,
            - How to define burst and cburst to appropriate values?
            - Default values within the Linux kernel?

    rtnl_htb_set_rbuffer(class, qdisc_att->burst);
    rtnl_htb_set_cbuffer(class, qdisc_att->cburst);
    */
  }  
      
  /* Submit request to kernel and wait for response */
  Logger::upf_app().info("Submit Class Creation Request to Kernel and Wait for Response");
  if ((err = rtnl_class_add(socket, qdisc_class, NLM_F_CREATE))) {
      Logger::upf_app().error("rtnl_class_add: Can not allocate the Class\n");
      return(err);
  }

  rtnl_class_put(qdisc_class);
}


/*---------------------------------------------------------------------------------------------------------------*/
/* Method to Release Netlink Objects (socket, qdisc)*/
void QdiscHelper::release_netlink_objects(struct nl_sock *socket, struct rtnl_class *qdisc_class){
    Logger::upf_app().info("Release Qdisc Object");
    rtnl_qdisc_delete(root_socket, root_qdisc);

    Logger::upf_app().info("Release Socket Object");
    nl_socket_free(root_socket);
} 


/*---------------------------------------------------------------------------------------------------------------*/
/* 
    Method to configure Parent Class object.
    Each Class represents a PDU Session.
    Rate = MBR
    Ceil = ?
    Priority = ?
    (pos->parentMaj, pos->parentMin) = (1, 0)
    (pos->childMaj, pos->childMin) = (1, SEID)*/
int QdiscHelper::configure_parent_class(struct nl_sock *socket, 
            struct rtnl_link *link, 
            struct rtnl_class *parent_class,
            struct class_params *class_att,
		    struct class_position *pos
)
{
    int err;

    Logger::upf_app().info("Set Parent Class Attributes:");
    rtnl_tc_set_link(TC_CAST(parent_class), link);
    rtnl_tc_set_parent(TC_CAST(parent_class), TC_HANDLE(pos->parentMaj, pos->parentMin));
    rtnl_tc_set_handle(TC_CAST(parent_class), TC_HANDLE(pos->childMaj, pos->childMin));
    
    if ((err = rtnl_tc_set_kind(TC_CAST(parent_class), class_att->scheduler))) {
      Logger::upf_app().error("Unable to set Scheduler %s to Parent Class", class_att->scheduler);
      return(err);
    }

    if (strcmp(rtnl_tc_get_kind(TC_CAST(qdisc_class)), HTB_SCHEDULER) == 0){
        rtnl_htb_set_prio(parent_class, class_att->priority);
        
        /*
        TODO: - Do we need to divide by 8 ?
            - rate = rate/8; 
            - ceil = ceil/8; 
        */

        if (class_att->rate > 0) {
            rtnl_htb_set_rate(parent_class, class_att->rate);
        }
        
        if (class_att->ceil > 0) {
            rtnl_htb_set_ceil(parent_class, class_att->ceil);
        }
        
        if (class_att->burst > 0) {
            rtnl_htb_set_rbuffer(parent_class, class_att->burst);
        }
        
        if (class_att->cburst > 0) {
            rtnl_htb_set_cbuffer(parent_class, class_att->cburst);
        }
    }

    /* Submit request to kernel and wait for response */
    if ((err = rtnl_class_add(socket, parent_class, NLM_F_CREATE))) {
        printf("Can not allocate the Parent Class\n");
        return 1;
    }
    rtnl_class_put(parent_class);
    return 0;
}


/*---------------------------------------------------------------------------------------------------------------*/
/* Method to configure Leaf Class object*/
void QdiscHelper::configure_leaf_class(struct nl_sock *socket, 
            struct rtnl_link *link, 
            struct rtnl_class *leaf_class,
            struct class_params *class_att,
		    struct class_position *pos
){
    int err;
    

    Logger::upf_app().info("Set Leaf Class Attributes:");
    rtnl_tc_set_link(TC_CAST(leaf_class), link);
    rtnl_tc_set_parent(TC_CAST(leaf_class), TC_HANDLE(pos->parentMaj, pos->parentMin));
    rtnl_tc_set_handle(TC_CAST(leaf_class), TC_HANDLE(pos->parentMin, 0));
    
    if ((err = rtnl_tc_set_kind(TC_CAST(leaf_class), class_att->scheduler))) {
      Logger::upf_app().error("Unable to set Scheduler %s to Leaf Class", class_att->scheduler);
      return(err);
    }

    if (strcmp(rtnl_tc_get_kind(TC_CAST(leaf_class)), HTB_SCHEDULER) == 0){
        
        if (class_att->priority > 0) {
            rtnl_htb_set_prio(leaf_class, class_att->priority);
        }

        /*
        TODO: - Do we need to divide by 8 ?
            - rate = rate/8; 
            - ceil = ceil/8; 
        */

        if (class_att->rate > 0) {
            rtnl_htb_set_rate(leaf_class, class_att->rate);
        }
        
        if (class_att->ceil > 0) {
            rtnl_htb_set_ceil(leaf_class, class_att->ceil);
        }
        
        if (class_att->burst > 0) {
            rtnl_htb_set_rbuffer(leaf_class, class_att->burst);
        }
        
        if (class_att->cburst > 0) {
            rtnl_htb_set_cbuffer(leaf_class, class_att->cburst);
        }
    }
    
    /* Submit request to kernel and wait for response */
    if ((err = rtnl_class_add(socket, leaf_class, NLM_F_CREATE))) {
        printf("Can not allocate the leaf Class\n");
        return 1;
    }

    rtnl_class_put(leaf_class);
    return 0;
}
