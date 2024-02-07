#ifndef __Get_NIC_INFORMATION_HPP__
#define __Get_NIC_INFORMATION_HPP__

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
  NicInformationGetter();

/*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the Scheduler object
   * 
   * @return const char* 
   */
   //const char *setScheduler(const char*);

/*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Retrieve the Transmission Rate of NIC  
   * 
   * @return uint32_t rate
   */
  uint32_t retrieveRate(std::string interface);

/*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Retrieve the Ceil transmission of NIC
   * 
   * @return uint32_t ceil
   */
  uint32_t retrieveCeil(std::string interface);

/*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Retrieve the Rate Buffer of the NIC
   * 
   * @return uint32_t rate_buffer
   */
  uint32_t retrieveRateBuffer(std::string interface);

/*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Retrieve the Ceil Buffer of the NIC
   * 
   * @return uint32_t ceil_buffer
   */
  uint32_t retrieveCeilBuffer(std::string interface);

/*---------------------------------------------------------------------------------------------------------------*/

 private:
  const std::string INTERFACE_DIR = "/sys/class/net/";
  //std::string executeCommand(const std::string& command);
};

#endif  //__Get_NIC_INFORMATION_HPP__