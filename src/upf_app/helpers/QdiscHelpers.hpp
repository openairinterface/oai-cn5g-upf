#ifndef __QDISC_HELPER_FUNCTIONS_HPP__
#define __QDISC_HELPER_FUNCTIONS_HPP__

#include <string>
#include <memory>
#include <netinet/ether.h>

#include "logger.hpp"


class QdiscHelper {
 public:
 /**
  * @brief Construct a new QdiscHelper object
  * 
  */
  QdiscHelper();


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a socket object
   * 
   * @return struct nl_sock* 
   */
  struct nl_sock *create_socket();
  
  
  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a qdisc object
   * 
   * @param socket 
   * @return struct rtnl_qdisc* 
   */
  struct rtnl_qdisc *create_qdisc(struct nl_sock *socket);


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a link cache object
   * 
   * @param socket 
   * @return struct nl_cache* 
   */
  struct nl_cache * create_link_cache(struct nl_sock *socket);


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a link object
   * 
   * @param iface 
   * @param link_cache 
   * @param socket 
   * @return struct rtnl_link* 
   */
  struct rtnl_link *create_link(const char *iface, struct nl_cache *link_cache, struct nl_sock *socket);
  
  
  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Configure the Root Qdisc
   * 
   * @param socket 
   * @param link 
   * @param qdisc 
   * @param qdisc_scheduler 
   * @param defaultClass 
   */
  void configure_root_qdisc(struct nl_sock *socket, struct rtnl_link *link, struct rtnl_qdisc *qdisc, const char *qdisc_scheduler, uint32_t defaultClass);


  /*------------------------------------------------------------------------------------------------------------------*/ 
  /**
   * @brief Configure Root Class
   * 
   * @param socket 
   * @param link 
   * @param qdisc_scheduler 
   * @param rate 
   * @param ceil 
   * @return * void 
   */
  void configure_root_class(struct nl_sock *socket, struct rtnl_link *link, struct rtnl_class *qdisc_class, const char *qdisc_scheduler, uint32_t rate, uint32_t ceil);
  
  
  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a Class to Attach to the Root Qdisc
   * 
   * @param socket
   */
  struct rtnl_class * create_class(struct nl_sock *socket);              
  
  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Release the Netlink Socket and Qdisc Objects
   * 
   * @param socket 
   * @param qdisc_class 
   */
  void release_netlink_objects(struct nl_sock *socket, struct rtnl_class *qdisc_class);
  /*------------------------------------------------------------------------------------------------------------------*/


};

#endif  // __GQDISC_HELPER_FUNCTIONS_HPP__
