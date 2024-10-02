UPF_WORKSPACE="${HOME}"/workspace
TREX_WORKSPACE=/tmp/workspace
DUT_UPF_WORKSPACE_STANDALONE="${UPF_WORKSPACE}"/oai-cn5g-upf
DUT_CN_WORKSPACE_STANDALONE="${UPF_WORKSPACE}"/oai-cn5g-fed
CN_DOCKER_COMPOSE_FILE=docker-compose-trex.yaml

UPF_N3_INTERFACE=enp1s0f0np0
UPF_N6_INTERFACE=enp1s0f1np1



DUT_SCAPY="${UPF_WORKSPACE}"/scapy





BPF_SAMPLES_DIR="${DUT_UPF_WORKSPACE_STANDALONE}"/build/samples
BPF_BINARY_DIR="${DUT_UPF_WORKSPACE_STANDALONE}"/build/tests

# Compilation environment variable.
NUM_THREADS=

# Docker environment variable.
USERNAME=upf-bpf
IMAGE_TAG=upf
IMAGE_VERSION=v2.1
DOCKERFILE=Dockerfile
DOCKERCOMPOSEFILE=docker-compose.yml
SSH_FOLDER=~/.ssh
SSH_PUBLIC_KEY_FILE=id_rsa.pub
SSH_PRIVATE_KEY_FILE=id_rsa
SSH_CONFIG_FILE=config
GIT_CONFIG=~/.gitconfig
BASH_RC=~/.bashrc

DEVICE_IN=
DEVICE_OUT_UL=
DEVICE_OUT_DL=

# TODO navarrothiago - pass as exec param.
GTP_INTERFACE=
UDP_INTERFACE=
SOCKET_BUFFER_ENABLED=0

# Test environment variables.
TEST_CASE=hello_world
GTEST_FILTER_ARGS="*.*"


########################################################
############## Trex Server Configuration ###############
########################################################
JUMP_SERVER_NAME="trex"
JUMP_SERVER_USERNAME="witcomm"
JUMP_SERVER_IP="www.opensource5g.org"
JUMP_SERVER_PORT=

# Trex server configuration.
TREX_SERVER_NAME="trex"
TREX_SERVER_IP="www.opensource5g.org"
TREX_SERVER_ASYNC_PORT="4501"
TREX_SERVER_SYNC_PORT="4500"
TREX_SERVER_USERNAME="witcomm"
TREX_SERVER_SSH="${TREX_SERVER_NAME}"
TREX_SERVER_SSH_ROOT="${TREX_SERVER_NAME}"
# TREX_SERVER_SSH="${TREX_SERVER_USERNAME}"@"${TREX_SERVER_IP}"
#TREX_VERSION=v3.00
TREX_VERSION=latest
TREX_EXTRACTED=v3.04
# TREX_VERSION=v2.87
#TREX_VERSION=v2.37
TREX_SHA256SUM=290c1be468335a2de2e69f217b139c9b1198732e529bfd069348d05297548b8a
TREX_SERVER_DOWNLOAD_DIR="${TREX_WORKSPACE}"
TREX_SERVER_DIR="${TREX_SERVER_DOWNLOAD_DIR}"/"${TREX_EXTRACTED}"

# Trex client configuration.
TREX_CLIENT_NAME= # Warning: Optional - If you set the name, it must be configured on your ssh config.
TREX_CLIENT_IP=
TREX_CLIENT_USERNAME=
TREX_CLIENT_SSH="${TREX_CLIENT_NAME}"
# TREX_CLIENT_SSH="${TREX_CLIENT_USERNAME}"@"${TREX_CLIENT_IP}"
TREX_CLIENT_UPLOAD_DIR="${TREX_WORKSPACE}"
TREX_CLIENT_DIR="${TREX_CLIENT_UPLOAD_DIR}"/trex_client
TREX_CLIENT_LIB_DIR="${TREX_CLIENT_DIR}"/interactive


########################################################
######## DUT - Device Under Test Configuration #########
########################################################
DUT_NAME="upf"
DUT_IP="www.opensource5g.org"
DUT_USERNAME="witcomm"
DUT_UPLOAD_DIR="${DUT_UPF_WORKSPACE_STANDALONE}"/package

# Test local configuration.
DUT_CONFIG_DIR="${DUT_UPF_WORKSPACE_STANDALONE}"/tests/trex/config
DUT_TRAFFIC_DIR="${DUT_UPF_WORKSPACE_STANDALONE}"/tests/trex/traffic
DUT_TEST_CASES_DIR="${DUT_UPF_WORKSPACE_STANDALONE}"/tests/trex/test_cases
DUT_SCRIPTS="${DUT_UPF_WORKSPACE_STANDALONE}"/tests/scripts
DUT_DEPLOYMENT="${DUT_UPF_WORKSPACE_STANDALONE}"/tests/deployment
DUT_SERVER_UPLOAD_DIR="${DUT_UPF_WORKSPACE_STANDALONE}"/tests/trex
DUT_PACKAGE="${DUT_UPF_WORKSPACE_STANDALONE}"/package

# Test remote configuration
TREX_CONFIG_DIR="${TREX_SERVER_DOWNLOAD_DIR}"/config
TREX_TRAFFIC_DIR="${TREX_SERVER_DOWNLOAD_DIR}"/traffic
TREX_TEST_CASES_DIR="${TREX_SERVER_DOWNLOAD_DIR}"/test_cases

# SSH port forwarding configuration
DUT_HTTP_SSH_PORT_FORWARDING="1234"
DUT_TREX_SYNC_SSH_PORT_FORWARDING="4501"
DUT_TREX_ASYNC_SSH_PORT_FORWARDING="4500"
API_HTTP_PORT="80"

# Programs name
API_PROGRAM_NAME=api

PYTHONPATH=/workspaces/tests/trex/trex_client/interactive/
