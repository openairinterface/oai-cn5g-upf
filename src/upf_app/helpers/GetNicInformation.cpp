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
#include <sstream>

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
uint64_t NicInformationGetter::retrieveRate(std::string interface) {
  // Paths to files containing interface information speed rate
  std::string speedPath = "/sys/class/net/" + interface + "/speed";

  // Read speed
  std::string speed = readValueFromFile(speedPath);

  uint64_t rate = 0;
  std::istringstream iss(speed);
  iss >> rate;

  return rate * 1000;
}

/*---------------------------------------------------------------------------------------------------------------*/
uint64_t NicInformationGetter::retrieveCeil(std::string interface) {
  // Paths to files containing interface information speed rate
  std::string speedPath = "/sys/class/net/" + interface + "/speed";

  // Read speed
  std::string speed = readValueFromFile(speedPath);

  uint64_t ceil = 0;
  std::istringstream iss(speed);
  iss >> ceil;

  return ceil * 1000;
}

/*---------------------------------------------------------------------------------------------------------------*/
uint32_t NicInformationGetter::retrieveBurst(std::string interface) {
  return 0;
}

/*---------------------------------------------------------------------------------------------------------------*/
uint32_t NicInformationGetter::retrieveCBurst(std::string interface) {
  return 0;
}
