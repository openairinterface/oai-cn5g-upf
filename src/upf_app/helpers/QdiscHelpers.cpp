#include "QdiscHelpers.hpp"

#include <netlink/netlink.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc/htb.h>




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

    if (!(qdisc_class = (struct rtnl_class *)rtnl_class_alloc())){
        Logger::upf_app().error("Unable to Allocate Qdisc Class Object");
        nl_socket_free(socket);
        return nullptr;
    }

    return qdisc_class;
}

