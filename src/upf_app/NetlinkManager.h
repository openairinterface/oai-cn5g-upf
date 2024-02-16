#include <iostream>
//#include <netlink/netlink.h>
#include <helpers/QdiscHelpers.hpp>

// Singleton class for managing the netlink socket and link


class NetlinkManager {
public:
    static NetlinkManager& getInstance(const std::string& gtpInterface);


/*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Destroy the Netlink Manager object
     * 
     */
    ~NetlinkManager();


/*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get the Socket object
     * 
     * @return struct nl_sock* 
     */
    struct nl_sock* getSocket();


/*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get the Link object
     * 
     * @return struct rtnl_link* 
     */
    struct rtnl_link* getLink();



/*---------------------------------------------------------------------------------------------------------------*/
    /**
     * @brief Get the Link_Cache object
     * 
     * @return struct nl_cache* 
     */
    struct nl_cache* getLinkCache();


/*---------------------------------------------------------------------------------------------------------------*/
    // Add other methods as needed


private:
    struct nl_sock *sock;
    struct rtnl_link *sockLink;
    struct nl_cache *sockLinkCache;
/*---------------------------------------------------------------------------------------------------------------*/    
    /**
     * @brief Construct a new Netlink Manager object
     * 
     */
    NetlinkManager(const std::string& gtpInterface);
};

