/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#ifndef CONFIG_LOADER_H
#define CONFIG_LOADER_H

#include <unordered_map>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>

class ConfigLoader {
 public:
  static ConfigLoader& getInstance() {
    static ConfigLoader instance;  // Singleton instance
    return instance;
  }

  bool loadConfig(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
      std::cerr << "Error: Cannot open config file " << filename << std::endl;
      return false;
    }

    std::string line;
    while (std::getline(file, line)) {
      std::istringstream is_line(line);
      std::string key;
      if (std::getline(is_line, key, '=')) {
        std::string value;
        if (std::getline(is_line, value)) {
          config[key] = std::stoi(value);
        }
      }
    }

    file.close();
    return true;
  }

  int getValue(const std::string& key, int default_value = 0) {
    return (config.find(key) != config.end()) ? config[key] : default_value;
  }

 private:
  ConfigLoader() {}  // Private constructor
  std::unordered_map<std::string, int> config;
};

#endif  // CONFIG_LOADER_H
