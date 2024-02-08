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
   * @brief Intialize the qdisc parameters
   * 
   * @param std::string interface
   */
  //void initialize_root_qdisc(std::string interface);

  /*------------------------------------------------------------------------------------------------------------------*/
  // /**
  //  * @brief Configure the HTB Qdisc
  //  * 
  //  */
  //   void configure_htb_qdisc();     

  /*------------------------------------------------------------------------------------------------------------------*/
  
    /**
     * @brief Create a Root Class to Attach to the Root Qdisc
     * 
     */
    struct rtnl_class * create_class(struct nl_sock *socket);              
  
  /*------------------------------------------------------------------------------------------------------------------*/
  // /**
  //  * @brief Configure the HTB root class with the NIC attributes
  //  * 
  //  */
  // void configure_htb_class();
  /*------------------------------------------------------------------------------------------------------------------*/


};

#endif  // __GQDISC_HELPER_FUNCTIONS_HPP__
