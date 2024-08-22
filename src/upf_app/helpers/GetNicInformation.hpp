#ifndef __GET_NIC_INFORMATION_HPP__
#define __GET_NIC_INFORMATION_HPP__

#include <string>
#include <memory>
#include <netinet/ether.h>

#include "logger.hpp"

class NicInformationGetter {
 public:
  /**
   * @brief Construct a new Nic Information Getter object
   *
   */
  // NicInformationGetter();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Retrieve the Transmission Rate of NIC
   *
   * @return uint32_t rate
   */
  static uint64_t retrieveRate(std::string interface);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Retrieve the Ceil transmission of NIC
   *
   * @return uint32_t ceil
   */
  static uint64_t retrieveCeil(std::string interface);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Retrieve the Rate Buffer of the NIC
   *
   * @return uint32_t rate_buffer
   */
  static uint32_t retrieveBurst(std::string interface);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Retrieve the Ceil Buffer of the NIC
   *
   * @return uint32_t ceil_buffer
   */
  static uint32_t retrieveCBurst(std::string interface);

  /*---------------------------------------------------------------------------------------------------------------*/

 private:
  // static const std::string INTERFACE_DIR = "/sys/class/net/";
};

#endif  //__GET_NIC_INFORMATION_HPP__