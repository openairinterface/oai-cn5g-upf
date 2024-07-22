//
// Created by root on 7/22/24.
//

#include "LocalRouting.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <iostream>
#include <cstring>
#include <csignal>
#include <arpa/inet.h>

namespace fr {

    bool LocalRouting::addRoute(RoutingInformation routing_information) {

        short ifIndex = this->getInterfaceIndex(routing_information.device);
        if (ifIndex == 0) {
            std::cerr << "Error: Invalid device name" << std::endl;
            return false;
        }

        int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (fd < 0) {
            std::cerr << "Error: Unable to create socket" << std::endl;
            return false;
        }
        struct rtentry route;
        std::memset(&route, 0, sizeof(route));
        struct sockaddr_in *addr;

        // Set destination address
        struct sockaddr_in* dest = reinterpret_cast<struct sockaddr_in*>(&route.rt_dst);
        dest->sin_family = AF_INET;
        inet_pton(AF_INET, routing_information.destination.c_str(), &dest->sin_addr);

/*        // Set gateway address (interface IP)
        struct sockaddr_in* gate = reinterpret_cast<struct sockaddr_in*>(&route.rt_gateway);
        gate->sin_family = AF_INET;
        inet_pton(AF_INET, "12.1.1.1", &gate->sin_addr);*/

        // Set netmask
        struct sockaddr_in* mask = reinterpret_cast<struct sockaddr_in*>(&route.rt_genmask);
        mask->sin_family = AF_INET;
        inet_pton(AF_INET, routing_information.networkMask.c_str(), &mask->sin_addr);

        // Set the interface index instead of the device name
        route.rt_dev = nullptr; // Not using device name directly
        route.rt_metric = 0;    // Metric is set to 0
        route.rt_flags = RTF_UP; // Only mark the route as up
        route.rt_metric = ifIndex; // Using metric to store interface index

        const auto ioctl_erro = ioctl(fd, SIOCADDRT, route);

        if (ioctl_erro < 0) {

            std::cerr << "Error: Unable to add route: " << strerror(errno) << std::endl;
            close(fd);
            return false;

        } else {
/*            this->routeInfoToRtEntry.insert({routing_information.destination,
                                             route});*/
            close(fd);
            return true;
        }

    }

    bool LocalRouting::deleteRoute(RoutingInformation routing_information) const {
/*      //  auto route = this->routeInfoToRtEntry.find(routing_information.destination);
        if (route != this->routeInfoToRtEntry.end()) {
            int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
            ioctl(fd, SIOCDELRT, route->second.get());
            close(fd);
            return false;
        }*/
        return false;
    }

    short LocalRouting::getInterfaceIndex(const std::string &interfaceName) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            std::cerr << "Error: Unable to create socket" << std::endl;
            return 0;
        }

        struct ifreq ifr;
        std::strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';

        if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
            std::cerr << "Error: Unable to get interface index" << std::endl;
            close(fd);
            return 0;
        }

        close(fd);
        return ifr.ifr_ifindex;
    }

} // fr