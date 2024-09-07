#!/usr/bin/env bash
#
# Run the t-rex on server.

main() {

  set -o errexit
  set -o pipefail
  set -o nounset

  local -r dirname="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local -r trex_extracted="${1:-v3.04}"
  source "${dirname}"/../env.sh

  echo
  echo "Run t-rex server on "${TREX_SERVER_IP}"."
  echo
  # https://superuser.com/questions/1138707/ssh-makes-all-typed-passwords-visible-when-command-is-provided-as-an-argument-to

  ssh -t "${TREX_SERVER_SSH}" \
    "cd ${TREX_SERVER_DOWNLOAD_DIR}/${trex_extracted} 
        sudo ./t-rex-64 -i --cfg ${TREX_CONFIG_DIR}/trex-dut-ip-config.yaml"
  exit 0
}
main "$@"

# sudo ./t-rex-64 -c6 -v 8 -i --cfg ${TREX_CONFIG_DIR}/platform_profile_dpdk.yaml"
