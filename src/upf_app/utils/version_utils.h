/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef VERSION_UTILS_H
#define VERSION_UTILS_H

#include <sys/utsname.h>
#include <cstdio>
#include <string>
#include <fstream>
#include <chrono>
#include <bpf/libbpf_version.h> 

namespace oai::upf::utils {

// Global variable to store process start time (initialized at program load)
static const auto g_process_start_time = std::chrono::steady_clock::now();

/**
 * @brief Package information structure
 */
struct PackageInfo {
  std::string branch;
  std::string commit_hash;
  std::string commit_date;
  std::string full_version;
};

//------------------------------------------------------------------------------
/**
 * @brief Get the full package version string
 * @return Full version string from PACKAGE_VERSION macro
 */
inline std::string GetPackageVersion() {
#ifdef PACKAGE_VERSION
  return std::string(PACKAGE_VERSION);
#else
  return "unknown";
#endif
}

//------------------------------------------------------------------------------
/**
 * @brief Parse package info from PACKAGE_VERSION string
 * @return PackageInfo struct with branch, commit_hash, and commit_date
 *
 * Parses format: "Branch: master Abrev. Hash: a1b2c3d Date: 2025-12-08"
 */
inline PackageInfo GetPackageInfo() {
  PackageInfo info;
  std::string version = GetPackageVersion();

#ifdef PACKAGE_VERSION
  info.full_version = std::string(PACKAGE_VERSION);

  // Parse: "Branch: master Abrev. Hash: a1b2c3d Date: 2025-12-08"
  std::string ver = info.full_version;

  // Extract branch
  size_t branch_pos = ver.find("Branch: ");
  if (branch_pos != std::string::npos) {
    size_t branch_start = branch_pos + 8;
    size_t branch_end   = ver.find(" ", branch_start);
    info.branch         = ver.substr(branch_start, branch_end - branch_start);
  }

  // Extract hash
  size_t hash_pos = ver.find("Hash: ");
  if (hash_pos != std::string::npos) {
    size_t hash_start = hash_pos + 6;
    size_t hash_end   = ver.find(" ", hash_start);
    info.commit_hash  = ver.substr(hash_start, hash_end - hash_start);
  }

  // Extract date
  size_t date_pos = ver.find("Date: ");
  if (date_pos != std::string::npos) {
    size_t date_start = date_pos + 6;
    info.commit_date  = ver.substr(date_start);
  }
#else
  info.full_version = "unknown";
  info.branch       = "unknown";
  info.commit_hash  = "unknown";
  info.commit_date  = "unknown";
#endif

  return info;
}

//------------------------------------------------------------------------------
/**
 * @brief Get the build date string
 * @return Build date (e.g., "2025-12-08") or compiler date
 */
inline std::string GetBuildDate() {
#ifdef BUILD_DATE
  return std::string(BUILD_DATE);
#else
  return std::string(__DATE__);  // Compiler fallback
#endif
}

//------------------------------------------------------------------------------
/**
 * @brief Get the build time string
 * @return Build time (e.g., "16:45:23") or compiler time
 */
inline std::string GetBuildTime() {
#ifdef BUILD_TIME
  return std::string(BUILD_TIME);
#else
  return std::string(__TIME__);  // Compiler fallback
#endif
}

//------------------------------------------------------------------------------
/**
 * @brief Get the kernel version string
 * @return Kernel version (e.g., "5.15.0-91-generic") or "unknown" on error
 */
inline std::string GetKernelVersion() {
  struct utsname uts;
  if (uname(&uts) == 0) {
    return std::string(uts.release);
  }
  return "unknown";
}

//------------------------------------------------------------------------------
/**
 * @brief Get the libbpf library version string
 * @return libbpf version (e.g., "1.7") or "unknown" if not available
 */
inline std::string GetLibbpfVersion() {
#if defined(LIBBPF_MAJOR_VERSION) && defined(LIBBPF_MINOR_VERSION)
  // libbpf >= 1.0 has version macros
  char version[32];
#ifdef LIBBPF_PATCH_VERSION
  snprintf(
      version, sizeof(version), "%d.%d.%d", LIBBPF_MAJOR_VERSION,
      LIBBPF_MINOR_VERSION, LIBBPF_PATCH_VERSION);
#else
  snprintf(
      version, sizeof(version), "%d.%d", LIBBPF_MAJOR_VERSION,
      LIBBPF_MINOR_VERSION);
#endif
  return std::string(version);
#elif defined(HAVE_LIBBPF)
  // Fallback for older libbpf versions
  return "< 1.0";
#else
  return "unknown";
#endif
}

//------------------------------------------------------------------------------
/**
 * @brief Get the system uptime string
 * @return System uptime (e.g., "22d 2h 47m") or "unknown" on error
 */
inline std::string GetSystemUptime() {
  std::ifstream uptime_file("/proc/uptime");
  if (uptime_file.is_open()) {
    double uptime_seconds;
    uptime_file >> uptime_seconds;
    uptime_file.close();

    int days    = static_cast<int>(uptime_seconds / 86400);
    int hours   = (static_cast<int>(uptime_seconds) % 86400) / 3600;
    int minutes = (static_cast<int>(uptime_seconds) % 3600) / 60;

    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%dd %dh %dm", days, hours, minutes);
    return std::string(buffer);
  }
  return "unknown";
}

//------------------------------------------------------------------------------
/**
 * @brief Get the UPF process uptime string
 * @return Process uptime (e.g., "0d 0h 5m") since UPF process started
 */
inline std::string GetProcessUptime() {
  auto now      = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::seconds>(
      now - g_process_start_time);

  long uptime_seconds = duration.count();
  int days            = uptime_seconds / 86400;
  int hours           = (uptime_seconds % 86400) / 3600;
  int minutes         = (uptime_seconds % 3600) / 60;

  char buffer[64];
  snprintf(buffer, sizeof(buffer), "%dd %dh %dm", days, hours, minutes);
  return std::string(buffer);
}

//------------------------------------------------------------------------------
/**
 * @brief Get the compiler version string
 * @return Compiler name and version (e.g., "GCC 11.4.0" or "Clang 14.0.0")
 */
inline std::string GetCompilerVersion() {
#if defined(__clang__)
  char version[64];
  snprintf(
      version, sizeof(version), "Clang %d.%d.%d", __clang_major__,
      __clang_minor__, __clang_patchlevel__);
  return std::string(version);
#elif defined(__GNUC__)
  char version[64];
  snprintf(
      version, sizeof(version), "GCC %d.%d.%d", __GNUC__, __GNUC_MINOR__,
      __GNUC_PATCHLEVEL__);
  return std::string(version);
#else
  return "unknown";
#endif
}

//------------------------------------------------------------------------------
/**
 * @brief Get CPU architecture
 * @return Architecture string (e.g., "x86_64", "aarch64")
 */
inline std::string GetArchitecture() {
  struct utsname uts;
  if (uname(&uts) == 0) {
    return std::string(uts.machine);
  }
  return "unknown";
}

//------------------------------------------------------------------------------
/**
 * @brief Get the bug report email address
 * @return Bug report email from PACKAGE_BUGREPORT macro or default
 */
inline std::string GetBugReportEmail() {
#ifdef PACKAGE_BUGREPORT
  return std::string(PACKAGE_BUGREPORT);
#else
  return "openaircn-user@lists.eurecom.fr";
#endif
}

}  // namespace oai::upf::utils

#endif  // VERSION_UTILS_H
