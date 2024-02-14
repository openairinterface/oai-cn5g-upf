#ifndef __QDISC_HELPER_FUNCTIONS_HPP__
#define __QDISC_HELPER_FUNCTIONS_HPP__

#include <string>
#include <memory>
#include <netinet/ether.h>
#include "qdisc_parameters.h"
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
   * @param qdisc_att 
   * @return int 
   */
  int configure_root_qdisc(struct nl_sock *socket, struct rtnl_link *link, struct rtnl_qdisc *qdisc, struct qdisc_root_params *qdisc_att );


  /*------------------------------------------------------------------------------------------------------------------*/ 
  /**
   * @brief Configure Root Class
   * 
   * @param socket 
   * @param link 
   * @param qdisc_class 
   * @param class_att 
   * @return int 
   */
  int configure_root_class(struct nl_sock *socket, struct rtnl_link *link, struct rtnl_class *qdisc_class, class_params *class_att);


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a Class to Attach to the Root Qdisc
   * 
   * @param socket
   */
  struct rtnl_class * create_class(struct nl_sock *socket);              
  

  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Configure Parent Qdisc Class
   * 
   * @param socket 
   * @param link 
   * @param parent_class 
   * @param class_att 
   * @param pos 
   * @return int 
   */
  int configure_parent_class(struct nl_sock *socket, struct rtnl_link *link, struct rtnl_class *parent_class, struct class_params *class_att, struct class_position *pos);

  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Configure the Leaf Qdisc Class
   * 
   * @param socket 
   * @param link 
   * @param leaf_class 
   * @param class_att 
   * @param pos 
   * @return int 
   */
  int configure_leaf_class(struct nl_sock *socket, struct rtnl_link *link, struct rtnl_class *leaf_class, struct class_params *class_att, struct class_position *pos);
  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Release the Netlink Socket and Qdisc Objects
   * 
   * @param socket 
   * @param qdisc_class 
   */
  void release_netlink_objects(struct nl_sock *socket, struct rtnl_qdisc *qdisc);
  /*------------------------------------------------------------------------------------------------------------------*/


};

#endif  // __GQDISC_HELPER_FUNCTIONS_HPP__
