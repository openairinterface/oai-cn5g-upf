#!/bin/bash

# ==============================================
# Author: Franck MESSAOUDI
# email: franck.messaoudi@openairinterface.org
#
# Script for testbed.
# Run the server and client on remote servers.
# Run control plane on dut.
#
# Packages required: tmux
# =============================================

send_keys_trex() {
  # Panel 0
  tmux send-keys -t "$session_name:0.0" "ssh ${TREX_SERVER_SSH}" C-m
  tmux send-keys -t "$session_name:0.0" "cd ${TREX_SERVER_DIR}" C-m 
  tmux send-keys -t "$session_name:0.0" "./t-rex-64 -i --cfg ${TREX_CONFIG_DIR}/trex-dut-ip-config.yaml" C-m

  # Panel 1
  tmux send-keys -t "$session_name:0.1" "sleep 7; ssh ${TREX_SERVER_NAME}" C-m
  tmux send-keys -t "$session_name:0.1" "cd ${TREX_TEST_CASES_DIR}; python3 run.py -m 100% -p mesfa -f udp -q $3 -d $4" C-m
}

send_keys_upf_logs() {
  # Panel 0
  tmux send-keys -t "$session_name:1.0" "ssh ${DUT_NAME}" C-m
  tmux send-keys -t "$session_name:1.0" "cd ${XDP_DUMP}" C-m
  tmux send-keys -t "$session_name:1.0" "sudo ./xdpdump -i enp5s0f1 --use-pcap -w $1/capture_$2_enp5s0f1.pcap" C-m

  # Panel 1
  tmux send-keys -t "$session_name:1.1" "ssh ${DUT_NAME}" C-m
  tmux send-keys -t "$session_name:1.1" "cd ${XDP_DUMP}" C-m
  tmux send-keys -t "$session_name:1.1" "sudo ./xdpdump -i enp5s0f0 -w $1/capture_$2_enp5s0f0.pcap" C-m

  # Panel 2
  tmux send-keys -t "$session_name:1.2" "ssh ${DUT_NAME}" C-m
  tmux send-keys -t "$session_name:1.2" "cd ${XDP_MONITOR}" C-m
  tmux send-keys -t "$session_name:1.2" "sudo ./xdp-monitor -e >> $1/xdp-monitor_$2.log" C-m
  
  # Panel 3
  tmux send-keys -t "$session_name:1.3" "ssh ${DUT_NAME}" C-m
  tmux send-keys -t "$session_name:1.3" "mpstat -P ALL 3 >> $1/cpu-usage_$2.log" C-m
}

create_window_trex() {
  tmux rename-window -t "$session_name:0" 'TRex'
  tmux split-window -h -t "$session_name:0.0"
  send_keys_trex "$1" "$2" "$3" "$4"
}

create_window_upf_logs() {
  tmux new-window -d -t "$session_name" -n 'UPF_logs'
  tmux split-window -h -t "$session_name:1.0"
  tmux split-window -h -t "$session_name:1.1"
  tmux split-window -v -t "$session_name:1.2"
  send_keys_upf_logs "$1" "$2"
}

attach() {
  echo "Attaching on session ${session_name}..."
  tmux select-pane -t "$session_name:0.0"
  tmux -2 attach-session -t "$session_name"
}

force_kill() {
  echo "Killing session ${session_name}..."
  tmux kill-session -t "$session_name" 2>/dev/null
}

stop() {
  echo "Stopping session ${session_name}..."
}

main() {
  set -o errexit
  set -o pipefail
  set -o nounset
  # set -x

  local -r dirname="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local -r filename="${dirname}/$(basename "${BASH_SOURCE[0]}")"
  local -r session_name="china"

  source "${dirname}/../env.sh"
  
  XDP_TOOLS="${WORKSPACE}/xdp-tools"
  XDP_DUMP="${XDP_TOOLS}/xdp-dump"
  XDP_MONITOR="${XDP_TOOLS}/xdp-monitor"
  SCRIPTS="${DUT_UPF_WORKSPACE_STANDALONE}/tests/scripts"
  
  unset TMUX

  tmux -2 new-session -d -s "$session_name"
  create_window_trex "$1" "$2" "$3" "$4"
  create_window_upf_logs "$1" "$2"
  attach
  stop
  force_kill
}

main "$@"
