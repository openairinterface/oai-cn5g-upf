#!/usr/bin/env bash
#
# Copy trex configuration.

main() {

  set -o errexit
  set -o pipefail
  set -o nounset

  local -r dirname="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  source "${dirname}"/../env.sh

  scp -r "${DUT_CONFIG_DIR}" "${TREX_SERVER_SSH}":"${TREX_SERVER_DOWNLOAD_DIR}"
  scp -r "${DUT_TRAFFIC_DIR}" "${TREX_SERVER_SSH}":"${TREX_SERVER_DOWNLOAD_DIR}"
  scp -r "${DUT_TEST_CASES_DIR}" "${TREX_SERVER_SSH}":"${TREX_SERVER_DOWNLOAD_DIR}"

  exit 0
}


main "$@"  