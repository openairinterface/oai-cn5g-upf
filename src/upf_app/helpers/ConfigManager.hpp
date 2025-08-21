#ifndef CONFIG_MANAGER_HPP
#define CONFIG_MANAGER_HPP
#include <sys/types.h>
class ConfigManager {
 public:
  // Returns the singleton instance
  static ConfigManager& getInstance();

  // Initializes the configuration
  void initialize(bool enableBpfDatapath, bool enableQos);

  // Checks if BPF datapath is enabled
  bool isBpfDatapathEnabled() const;

  // Checks if QoS is enabled
  bool isQosEnabled() const;

 private:
  // Private constructor to prevent instantiation
  ConfigManager() = default;

  // Deleted copy constructor and assignment operator
  ConfigManager(const ConfigManager&) = delete;
  ConfigManager& operator=(const ConfigManager&) = delete;

  // Configuration variables
  bool enable_bpf_datapath = false;
  bool enable_qos          = false;

  u_int16_t max_upf_interfaces              = 8;
  u_int16_t max_upf_redirect_interfaces     = 4;
  u_int16_t max_pdu_session                 = 10000;
  u_int16_t max_pdrs_per_pdu_session        = 8;
  u_int16_t max_qos_flows_per_pdu_session   = 8;
  u_int16_t max_sdf_filters_per_pdu_session = 8;
  u_int16_t max_arp_entries                 = 1572;
};

#endif  // CONFIG_MANAGER_HPP