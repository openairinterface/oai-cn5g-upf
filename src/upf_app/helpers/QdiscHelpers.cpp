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
struct nl_sock *QdiscHelper::createSocket(){
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
struct rtnl_qdisc *QdiscHelper::createQdisc(struct nl_sock *socket){
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
struct nl_cache *QdiscHelper::createLinkCache(struct nl_sock *socket){
    int err;
    struct nl_cache *linkCache;
    
    Logger::upf_app().info("Create a Netlink Link Cache object");
    
    if ((err = rtnl_link_alloc_cache(socket, AF_UNSPEC, &linkCache)) < 0) {
        Logger::upf_app().error("Unable to allocate link cache: %s\n", nl_geterror(err));
        nl_socket_free(socket);
        return nullptr;
    } 

    return linkCache; 
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method to create a link object
struct rtnl_link *QdiscHelper::createLink(const char *iface, struct nl_cache *linkCache, struct nl_sock *socket){
  
  struct rtnl_link *link;
  Logger::upf_app().info("Create a Netlink Link object");
  
  if (!(link = rtnl_link_get_by_name(linkCache, iface))) {
    Logger::upf_app().error("rtnl_link_get_by_name: Interface %s not found\n", iface);
    nl_socket_free(socket);
    return nullptr;
  }

  return link;
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method to create a qdisc class object
struct rtnl_class *QdiscHelper::createClass(struct nl_sock *socket){      
    int err;
    struct rtnl_class *qdiscClass;  

    Logger::upf_app().info("Create a Qdisc Class");

    if (!(qdiscClass = rtnl_class_alloc())){
        Logger::upf_app().error("Unable to Allocate Qdisc Class Object");
        nl_socket_free(socket);
        return nullptr;
    }

    return qdiscClass;
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method to configure the root qdisc object
int QdiscHelper::configureRootQdisc(struct nl_sock *socket, 
    struct rtnl_link *link,
    struct rtnl_qdisc *qdisc,
    struct qdiscRootParams *qdiscAtt
    )
{    
  int err;

  Logger::upf_app().info("Delete Existing Qdisc");
  rtnl_qdisc_delete(socket, qdisc);
  //rtnl_qdisc_put(qdisc);
    
  Logger::upf_app().info("Set the Root Qdisc Attributes");
  //rtnl_tc_set_ifindex(TC_CAST(qdisc), master_index);
  rtnl_tc_set_link(TC_CAST(qdisc), link);
  rtnl_tc_set_parent(TC_CAST(qdisc), TC_H_ROOT);

  rtnl_tc_set_handle(TC_CAST(qdisc), TC_HANDLE(1,0));
  if ((err = rtnl_tc_set_kind(TC_CAST(qdisc), qdiscAtt->scheduler))) {
    Logger::upf_app().error("rtnl_tc_set_kind: Cannot allocate :%s\n", qdiscAtt->scheduler);
    return(err);
  }
  
  Logger::upf_app().info("Set Default Class for Unclassified Traffic");
  rtnl_htb_set_defcls(qdisc, TC_HANDLE(1, qdiscAtt->defaultClass));
  rtnl_htb_set_rate2quantum(qdisc, qdiscAtt->quantum);
  
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
int QdiscHelper::configureRootClass(struct nl_sock *socket,
    struct rtnl_link *link,
    struct rtnl_class *qdiscClass,
    classParams *classAtt
    ){
  int err;

  Logger::upf_app().info("Set Root Class Attributes:");
  rtnl_tc_set_link(TC_CAST(qdiscClass), link);
  rtnl_tc_set_parent(TC_CAST(qdiscClass), TC_H_ROOT);
  rtnl_tc_set_handle(TC_CAST(qdiscClass), 1);
  
  if ((err = rtnl_tc_set_kind(TC_CAST(qdiscClass), classAtt->scheduler))) {
      Logger::upf_app().error("Unable to set Scheduler %s to Class", classAtt->scheduler);
      return(err);
  }

  if (strcmp(rtnl_tc_get_kind(TC_CAST(qdiscClass)), HTB_SCHEDULER) == 0){
	/*
      TODO: - Do we need to divide by 8 ?
            - rate = rate/8; 
            - ceil = ceil/8; 
    */
    if ((classAtt->rate) > 0) {
        rtnl_htb_set_rate(qdiscClass, classAtt->rate);
    }

    if ((classAtt->ceil) > 0) {        
	    rtnl_htb_set_ceil(qdiscClass, classAtt->ceil);
    }
  
    /*
    TODO: - Check if we need burst and cburst values,
            - How to define burst and cburst to appropriate values?
            - Default values within the Linux kernel?

    rtnl_htb_set_rbuffer(class, qdiscAtt->burst);
    rtnl_htb_set_cbuffer(class, qdiscAtt->cburst);
    */
  }  
      
  /* Submit request to kernel and wait for response */
  Logger::upf_app().info("Submit Class Creation Request to Kernel and Wait for Response");
  if ((err = rtnl_class_add(socket, qdiscClass, NLM_F_CREATE))) {
      Logger::upf_app().error("rtnl_class_add: Can not allocate the Class\n");
      return(err);
  }

  rtnl_class_put(qdiscClass);
  return 0;
}


/*---------------------------------------------------------------------------------------------------------------*/
/* Method to Release Netlink qdisc (socket, qdisc)*/
void QdiscHelper::releaseNetlinkQdisc(struct nl_sock *socket, struct rtnl_qdisc *qdisc){
    Logger::upf_app().info("Release Qdisc Object");
    rtnl_qdisc_delete(socket, qdisc);
} 


/*---------------------------------------------------------------------------------------------------------------*/
/* Method to Release Netlink socket */
void QdiscHelper::releaseNetlinkSocket(struct nl_sock *socket){
    Logger::upf_app().info("Release Socket Object");
    nl_socket_free(socket);
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
int QdiscHelper::configureParentClass(struct nl_sock *socket, 
            struct rtnl_link *link, 
            struct rtnl_class *parentClass,
            struct classParams *classAtt,
		    struct classPosition *pos
)
{
    int err;

    Logger::upf_app().info("Set Parent Class Attributes:");
    rtnl_tc_set_link(TC_CAST(parentClass), link);
    rtnl_tc_set_parent(TC_CAST(parentClass), TC_HANDLE(pos->parentMaj, pos->parentMin));
    rtnl_tc_set_handle(TC_CAST(parentClass), TC_HANDLE(pos->childMaj, pos->childMin));
    
    if ((err = rtnl_tc_set_kind(TC_CAST(parentClass), classAtt->scheduler))) {
      Logger::upf_app().error("Unable to set Scheduler %s to Parent Class", classAtt->scheduler);
      return(err);
    }

    if (strcmp(rtnl_tc_get_kind(TC_CAST(parentClass)), HTB_SCHEDULER) == 0){
        rtnl_htb_set_prio(parentClass, classAtt->priority);
        
        /*
        TODO: - Do we need to divide by 8 ?
            - rate = rate/8; 
            - ceil = ceil/8; 
        */

        if (classAtt->rate > 0) {
            rtnl_htb_set_rate(parentClass, classAtt->rate);
        }
        
        if (classAtt->ceil > 0) {
            rtnl_htb_set_ceil(parentClass, classAtt->ceil);
        }
        
        if (classAtt->burst > 0) {
            rtnl_htb_set_rbuffer(parentClass, classAtt->burst);
        }
        
        if (classAtt->cburst > 0) {
            rtnl_htb_set_cbuffer(parentClass, classAtt->cburst);
        }
    }

    /* Submit request to kernel and wait for response */
    if ((err = rtnl_class_add(socket, parentClass, NLM_F_CREATE))) {
        printf("Can not allocate the Parent Class\n");
        return 1;
    }
    rtnl_class_put(parentClass);
    return 0;
}


/*---------------------------------------------------------------------------------------------------------------*/
/* Method to configure Leaf Class object*/
int QdiscHelper::configureLeafClass(struct nl_sock *socket, 
            struct rtnl_link *link, 
            struct rtnl_class *leafClass,
            struct classParams *classAtt,
		    struct classPosition *pos
){
    int err;
    

    Logger::upf_app().info("Set Leaf Class Attributes:");
    rtnl_tc_set_link(TC_CAST(leafClass), link);
    rtnl_tc_set_parent(TC_CAST(leafClass), TC_HANDLE(pos->parentMaj, pos->parentMin));
    rtnl_tc_set_handle(TC_CAST(leafClass), TC_HANDLE(pos->parentMin, 0));
    
    if ((err = rtnl_tc_set_kind(TC_CAST(leafClass), classAtt->scheduler))) {
      Logger::upf_app().error("Unable to set Scheduler %s to Leaf Class", classAtt->scheduler);
      return(err);
    }

    if (strcmp(rtnl_tc_get_kind(TC_CAST(leafClass)), HTB_SCHEDULER) == 0){
        
        if (classAtt->priority > 0) {
            rtnl_htb_set_prio(leafClass, classAtt->priority);
        }

        /*
        TODO: - Do we need to divide by 8 ?
            - rate = rate/8; 
            - ceil = ceil/8; 
        */

        if (classAtt->rate > 0) {
            rtnl_htb_set_rate(leafClass, classAtt->rate);
        }
        
        if (classAtt->ceil > 0) {
            rtnl_htb_set_ceil(leafClass, classAtt->ceil);
        }
        
        if (classAtt->burst > 0) {
            rtnl_htb_set_rbuffer(leafClass, classAtt->burst);
        }
        
        if (classAtt->cburst > 0) {
            rtnl_htb_set_cbuffer(leafClass, classAtt->cburst);
        }
    }
    
    /* Submit request to kernel and wait for response */
    if ((err = rtnl_class_add(socket, leafClass, NLM_F_CREATE))) {
        printf("Can not allocate the leaf Class\n");
        return err;
    }

    rtnl_class_put(leafClass);
    return 0;
}
