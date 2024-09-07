#!/usr/bin/env bash
#
# Install the t-rex on server.

RED="\e[31m"
GREEN="\e[32m"
ENDCOLOR="\e[0m"

server_config(){
  echo
  echo "Installing trex on "${TREX_SERVER_IP}""
  echo
  echo -e "${GREEN}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  echo 
  echo "Trex Has the following configuration :"
  echo 
  echo "    Trex Management IP -------------: "${TREX_SERVER_IP}""
  echo "    Trex Hostname ------------------: "${TREX_SERVER_NAME}""
  echo "    Trex Username ------------------: "${TREX_SERVER_USERNAME}""
  echo "    Trex App Version ---------------: "${TREX_VERSION}""
  echo "    Trex Install Dir ---------------: "${TREX_SERVER_DOWNLOAD_DIR}"/"${TREX_VERSION}""
  echo "    Trex sha256sum -----------------: "${TREX_SHA256SUM}""
  echo    
  echo -e "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${ENDCOLOR}"
  echo 
}



main() {
   set -o errexit
   set -o pipefail
   set -o nounset
  # set -x

  local -r dirname="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  source "${dirname}"/../env.sh
  
  server_config
  # Execute local script (install_trex) on the server.  
  echo "SSH to Trex ..."
  ssh "${TREX_SERVER_SSH}" "bash -s" -- "${TREX_SERVER_DOWNLOAD_DIR}" "${TREX_VERSION}" <"${dirname}"/install_trex.sh
}

main "$@"