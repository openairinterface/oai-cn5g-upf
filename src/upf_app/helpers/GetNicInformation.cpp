#include "GetNicInformation.hpp"
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <types.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <fstream>
#include <string>

#include <stdexcept>
#include <arpa/inet.h>



#define COMMAND_MAX_LENGTH 256
#define OUTPUT_MAX_LENGTH 256

/*---------------------------------------------------------------------------------------------------------------*/
// Function to read a value from a file
std::string readValueFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Error: Failed to open file " << path << std::endl;
        return "";
    }

    std::string value;
    file >> value;
    file.close();
    return value;
}


/*---------------------------------------------------------------------------------------------------------------*/

NicInformationGetter::NicInformationGetter() {}

/*---------------------------------------------------------------------------------------------------------------*/
// const char *NicInformationGetter::setScheduler(const char*) {
  
// }

/*---------------------------------------------------------------------------------------------------------------*/
uint32_t NicInformationGetter::retrieveRate(std::string interface) {
  // Paths to files containing interface information speed rate
    std::string speedPath = INTERFACE_DIR + interface + "/speed";
    
    // Read speed
    std::string speed = readValueFromFile(speedPath);

    uint32_t rate = 0;
    std::istringstream iss(speed);
    iss >> rate;

    return rate;
}

/*---------------------------------------------------------------------------------------------------------------*/
uint32_t NicInformationGetter::retrieveCeil(std::string interface) {
 // Paths to files containing interface information speed rate
  std::string speedPath = INTERFACE_DIR + interface + "/speed";
  
  // Read speed
  std::string speed = readValueFromFile(speedPath);

  uint32_t ceil = 0;
  std::istringstream iss(speed);
  iss >> ceil;

  return ceil;
}

/*---------------------------------------------------------------------------------------------------------------*/
// uint32_t NicInformationGetter::retrieveCeil(std::string interface) {
//   return NicInformationGetter::retrieveRate(interface);
// }

/*---------------------------------------------------------------------------------------------------------------*/
uint32_t NicInformationGetter::retrieveRateBuffer(std::string interface) {
//   char command[COMMAND_MAX_LENGTH];

//   struct in_addr addr;
//   addr.s_addr     = next_hop_ip;
//   char* ipAddress = inet_ntoa(addr);

//   if (ipAddress == nullptr) {
//     Logger::upf_app().error("The Next Hop IPv4 WAS NOT Retrieved");
//     throw std::runtime_error("The Next Hop IPv4 WAS NOT Retrieved");
//   }

//   sprintf(command, "sudo arping -c 1 %s | awk '/from/ {print $4}'", ipAddress);
//   // Logger::upf_app().debug("Next Hop SRC IP = %s", ipAddress);
//   Logger::upf_app().debug(
//       "Next Hop <SRC IP, MAC Address> = <%s, %s>", ipAddress,
//       executeCommand(command).c_str());

//   ether_addr* next_hop_mac = {};
//   next_hop_mac = ether_aton(executeCommand(command).c_str());

//   if (next_hop_mac == nullptr) {
//     Logger::upf_app().error("The Next Hop MAC WAS NOT Retrieved");
//     throw std::runtime_error("The Next Hop MAC WAS NOT Retrieved");
//   }

//   return next_hop_mac;
}

/*---------------------------------------------------------------------------------------------------------------*/
uint32_t NicInformationGetter::retrieveCeilBuffer(std::string interface) {
}

/*---------------------------------------------------------------------------------------------------------------*/

std::string NicInformationGetter::executeCommand(const std::string& command) {
  char output[OUTPUT_MAX_LENGTH];
  FILE* fp = popen(command.c_str(), "r");

  if (fp == nullptr) {
    Logger::upf_app().error("Failed to Run the Command: %s\n", command.c_str());
    return "";
  }

  fgets(output, OUTPUT_MAX_LENGTH, fp);
  pclose(fp);
  return output;
}

/*---------------------------------------------------------------------------------------------------------------*/
