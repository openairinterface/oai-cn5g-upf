#include <iostream>
#include <netlink/netlink.h>
#include "NetlinkManager.h"

// Singleton class for managing the netlink socket and link

NetlinkManager::NetlinkManager(const std::string& gtpInterface) {
  QdiscHelper qdiscHelper;

  if (!(sock = qdiscHelper.createSocket())) {
    Logger::upf_app().error("Unable to create a netlink socket");
    exit(EXIT_FAILURE);
  }

  if (!(sockLinkCache = qdiscHelper.createLinkCache(sock))) {
    Logger::upf_app().error("Unable to create a link cache");
    exit(EXIT_FAILURE);
  }

  if (!(sockLink = qdiscHelper.createLink(
            gtpInterface.c_str(), sockLinkCache, sock))) {
    Logger::upf_app().error("Unable to create a link");
    exit(EXIT_FAILURE);
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
NetlinkManager& NetlinkManager::getInstance(const std::string& gtpInterface) {
  static NetlinkManager sInstance(gtpInterface);
  return sInstance;
}

/*---------------------------------------------------------------------------------------------------------------*/
struct nl_sock* NetlinkManager::getSocket() {
  return sock;
}

/*---------------------------------------------------------------------------------------------------------------*/
struct nl_cache* NetlinkManager::getLinkCache() {
  return sockLinkCache;
}

/*---------------------------------------------------------------------------------------------------------------*/
struct rtnl_link* NetlinkManager::getLink() {
  return sockLink;
}

/*---------------------------------------------------------------------------------------------------------------*/
NetlinkManager::~NetlinkManager() {
  QdiscHelper qdiscHelper;
  qdiscHelper.releaseNetlinkSocket(sock);
}
