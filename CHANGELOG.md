# RELEASE NOTES: #

## v2.1.0 -- August 2024 ##

* Features
  - Add connection handling between UPF and NRF
  - Use HTTP Request Timeout parameter from Conf file
  - QoS initial support
  - N4 interoperability improved
  - Performance improvement: CPU usage is further reduced
* Fixes
  - Fixes: thread management especially at shutdown.
  - Fix FDQN IPv4-only resolution
  - Fix Using SD in string hex in UPF profile to send to NRF
  - Fix to update TEID after a reconnection with FiveG_S_TMSI
* Tech Debt
  - Stopping support for RHEL8/Rocky8 in favor of RHEL9/Rocky9
  - Remove NRF dependency from UPF
  - HTTP client cpr library refactoring effort
  - Bumping up libbpf and bpftool versions:
    - libbpf to `master` (currently above `v1.4.5`)
    - bpftool to `v7.3.0`
    - This should allow to build on newer systems

## v2.0.0 -- December 2023 ##

* Features
  - Support YAML configuration file
    * Yaml validation default value
  - Implemented an eBPF-based solution in parallel of the current Simple-Switch solution
    * This is a runtime option
  - De-register towards NRF on exit
  - Enable PFCP association request for no NRF case
* Tech debt
  - Switching to clang-format-12
  - Published image on Docker-Hub is using now Ubuntu-22 as base image
  - Ubuntu-18 is no longer supportable due to eBPF

## v1.5.1 -- May 2023 ##

* Support for rocky linux 8.7
* Increasing size of hashmap tables
* Code Refactoring for:
  * Logging mechanism (runtime log level selection)
* Published image on Docker-Hub is using now Ubuntu-20 as base image
  * We will soon obsolete the build system for Ubuntu18.04

## v1.5.0 -- January 2023 ##

* feat(fqdn): giving some time for FQDN resolution
* Docker image improvements
* Fixed docker exit by catching SIGTERM
* Ubuntu22 full support

## v1.4.0 -- July 2022 ##

* Fix for handling S-NSSAI 
* Add support for multiple slices via config file
* Allowed reusing GTPv1-U socket
* Fix GTPU offset sequence number
* Fix configurable number of DL threads for data path
* Official images produced by CI are pushed to `oaisoftwarealliance` Docker-Hub Team account
* Reduce image size
* Skipping release tag v1.3.0 to be in sync with OAI CN 5G network functions

## v1.2.0 -- February 2022 ##

* Obsolescence of Legacy OAI-MME
* Build fixes
* Docker image layer optimization

## v1.1.5 -- December 2021 ##

* Disable association request if NF registration is enabled

## v1.1.4 -- October 2021 ##

* Fix build issue
* Fix GTPU DL encapsulation: 8 extraneous bytes

## v1.1.3 -- October 2021 ##

* Adding 5G features
  - HTTP2 support

## v1.1.2 -- July 2021 ##

* Adding 5G features
  - NRF discovery and FQDN support

## v1.1.1 -- March 2021 ##

* GTP-U extension headers for 5G support
  - disabled by default for 4G usage

## v1.1.0 -- February 2021 ##

*  Cloud-native support
*  RHEL8 support
*  A lot of bug fixes/improvements
   -  TCP checksum fix --> better TCP throughput
   -  Multi-Threading
   -  Protection to prevent running multiple times the executable
   -  ...
*  Last release before Multi-UPF-instance support

## v1.0.0 -- May 2019 ##

* First release, Able to serve a MME with basic attach, detach, release, paging procedures, default bearer only.
