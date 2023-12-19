# Install t-rex.






main() {
  echo "Trex Install ...!"
  set -o errexit
  set -o pipefail
  set -o nounset
  #set -x
  
  local -r dirname="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  local -r download_dir="${1:-/tmp}"
  local -r trex_version="${2:-v3.0}"
  local -r trex_shasum="${3:-290c1be468335a2de2e69f217b139c9b1198732e529bfd069348d05297548b8a}"
  local -r shasum=$(cat "${download_dir}"/"${trex_version}".tar.gz | sha256sum | awk '{print $1}')
  local -r trex_dir="${download_dir}"/"${trex_version}"
  local -r trex_client_dir="${download_dir}"/trex_client

  # echo
  # echo "Installation folder: "${download_dir}""
  # echo "Installation version: "${trex_version}""
  # echo "Installation sha256sum: "${trex_shasum}""
  # echo

  mkdir -p "${download_dir}"
  # [ Check if trex not exist OR
  #   Check if trex has different checksum ] AND
  # [ Check if the installation directoy not exist ] .
  if [ ! -f "${download_dir}"/"${trex_version}".tar.gz ] \
        || [ "${trex_shasum}" != "${shasum}" ] \
        && [ ! -d "${trex_dir}" ]; then
    rm -f "${download_dir}"/"${trex_version}".tar.gz
    cd "${download_dir}"
    wget --no-cache --no-check-certificate https://trex-tgn.cisco.com/trex/release/"${trex_version}".tar.gz
    tar -xzvf "${trex_version}".tar.gz
    tar -xzvf "${trex_version}"/trex_client_"${trex_version}".tar.gz
    rm "${trex_version}".tar.gz
  fi

  # Check if trex client directoty not exists AND tar.gz exists
  if [ ! -d "${trex_client_dir}" ] &&  [ -f "${trex_dir}"/trex_client_"${trex_version}".tar.gz ]; then
    echo "Installing the trex client..."
    mkdir -p "${trex_client_dir}"
    # trex_client must exist. Do not untar inside the trex_client_dir in order to avoid
    # create two trex_client nested folder.
    tar -xzvf "${trex_dir}"/trex_client_"${trex_version}".tar.gz -C "${download_dir}"
    echo "Done!"
  fi

  echo "The t-rex installation was successful!"

  exit 0
}

main "$@"