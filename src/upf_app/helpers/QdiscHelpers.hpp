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
  struct nl_sock *createSocket();
  
  
  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a qdisc object
   * 
   * @param struct nl_sock* 
   * @return struct rtnl_qdisc* 
   */
  struct rtnl_qdisc *createQdisc(struct nl_sock *socket);


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a link cache object
   * 
   * @param socket 
   * @return struct nl_sock*
   */
  struct nl_cache * createLinkCache(struct nl_sock *socket);


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a link object
   * 
   * @param const char*
   * @param struct nl_cache*
   * @param struct nl_sock*
   * @return struct rtnl_link* 
   */
  struct rtnl_link *createLink(const char *iface, struct nl_cache *linkCache, struct nl_sock *socket);
  
  
  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Configure the Root Qdisc
   * 
   * @param struct nl_sock*
   * @param struct rtnl_link* 
   * @param struct rtnl_qdisc*
   * @param struct qdiscRootParams*
   * @return int 
   */
  int configureRootQdisc(struct nl_sock *socket, struct rtnl_link *link, struct rtnl_qdisc *qdisc, struct qdiscRootParams *qdiscAtt );


  /*------------------------------------------------------------------------------------------------------------------*/ 
  /**
   * @brief Configure Root Class
   * 
   * @param struct nl_sock*
   * @param struct rtnl_link*
   * @param struct rtnl_class*
   * @param classParams*
   * @return int 
   */
  int configureRootClass(struct nl_sock *socket, struct rtnl_link *link, struct rtnl_class *qdiscClass, classParams *classAtt);


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a Class to Attach to the Root Qdisc
   * 
   * @param struct nl_sock*
   * @return struct rtnl_class*
   */
  struct rtnl_class* createClass(struct nl_sock *socket);              
  

  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Configure Parent Qdisc Class
   * 
   * @param struct nl_sock*
   * @param struct rtnl_link*
   * @param struct rtnl_class*
   * @param struct classParams*
   * @param struct classPosition*
   * @return int 
   */
  int configureParentClass(struct nl_sock *socket, struct rtnl_link *link, struct rtnl_class *parentClass, struct classParams *classAtt, struct classPosition *pos);


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Configure the Leaf Qdisc Class
   * 
   * @param struct nl_sock*  
   * @param struct rtnl_link*
   * @param struct rtnl_class*
   * @param struct classParams*
   * @param struct classPosition*
   * @return int 
   */
  int configureLeafClass(struct nl_sock *socket, struct rtnl_link *link, struct rtnl_class *leafClass, struct classParams *classAtt, struct classPosition *pos);


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Release the Netlink Qdisc Object
   * 
   * @param struct nl_sock*
   * @param struct rtnl_qdisc*
   */
  void releaseNetlinkQdisc(struct nl_sock *socket, struct rtnl_qdisc *qdisc);


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Method to Release Netlink socket 
   * 
   * @param socket 
   */
  void releaseNetlinkSocket(struct nl_sock *socket);


  /*------------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Method to Release Netlink class 
   * 
   * @param rtnl_class *qdiscClass
   */
  void releaseNetlinkClass(struct rtnl_class *qdiscClass);

};

#endif  // __GQDISC_HELPER_FUNCTIONS_HPP__
