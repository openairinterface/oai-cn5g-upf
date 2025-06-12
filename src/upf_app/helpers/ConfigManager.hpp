#ifndef CONFIG_MANAGER_HPP
#define CONFIG_MANAGER_HPP

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
};

#endif  // CONFIG_MANAGER_HPP