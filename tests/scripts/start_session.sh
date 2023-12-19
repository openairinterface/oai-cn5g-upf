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
#=============================================

#Create remote session with panes


configure_layout(){
  tmux split-window -t $1:$2.$3 $4
}


resize_panel(){
  tmux resize-pane -t $1:$2.$3 $4 $5
}


send_keys_upf(){
  #---------------------------------------------------------#
  #                        PANEL 0                          #
  #---------------------------------------------------------#
  tmux send-keys -t $session_name:0.0 "ssh "${DUT_NAME}"" C-m
  tmux send-keys -t $session_name:0.0 "cd "${DUT_UPF_WORKSPACE_STANDALONE}"" C-m
  tmux send-keys -t $session_name:0.0 "ip link set dev demo-n3 xdp off; ip link set dev demo-n6 xdp off" C-m
  #tmux send-keys -t $session_name:0.0 "make clean && make setup && make install" C-m
  tmux send-keys -t $session_name:0.0 "upf -o -c etc/config.yaml" C-m

  #---------------------------------------------------------#
  #                        PANEL 1                          #
  #---------------------------------------------------------#
  tmux send-keys -t $session_name:0.1 "ssh "${DUT_NAME}"" C-m
  #tmux send-keys -t $session_name:0.1 "sleep 240" C-m
  tmux send-keys -t $session_name:0.1 "bpftool prog tracelog" C-m

  #---------------------------------------------------------#
  #                        PANEL 2                          #
  #---------------------------------------------------------#
  # tmux send-keys -t $session_name:0.2 "ssh "${DUT_NAME}"" C-m
  # tmux send-keys -t $session_name:0.2 "cd "${DUT_DEPLOYMENT}"" C-m
  # tmux send-keys -t $session_name:0.2 "sleep 3" C-m
  # tmux send-keys -t $session_name:0.2 "apt-get install scapy" C-m
  # tmux send-keys -t $session_name:0.2 "python3 pfcp_requests.py" C-m

  #---------------------------------------------------------#
  #                        PANEL 3                          #
  #---------------------------------------------------------#
  tmux send-keys -t $session_name:0.3 "ssh "${DUT_NAME}"" C-m
  tmux send-keys -t $session_name:0.3 "echo "1" > /proc/sys/net/ipv4/ip_forward" C-m
  #tmux send-keys -t $session_name:0.3 "apt-get install -y sysstat" C-m
  #tmux send-keys -t $session_name:0.3 "sleep 60" C-m
  tmux send-keys -t $session_name:0.3 "mpstat -P ALL 3" C-m
}



remove_trex(){
  if ssh trex [ -d "/tmp/trex_client" ] 
  then
    ssh trex rm -rf /tmp/trex_client 
  fi

  if ssh trex [ -d "/tmp/v3.00" ]
  then 
    ssh trex rm -rf /tmp/v3.00 
  fi
}



send_keys_trex(){
  #---------------------------------------------------------#
  #                        PANEL 0                          #
  #---------------------------------------------------------#
  tmux send-keys -t $session_name:1.0 "ssh "${TREX_SERVER_NAME}"" C-m
  #tmux send-keys -t $session_name:1.0 "echo "1" > /proc/sys/net/ipv4/ip_forward" C-m
  #tmux send-keys -t $session_name:1.0 "echo off > /sys/devices/system/cpu/smt/control" C-m
  tmux send-keys -t $session_name:1.0 "cd /tmp/"${TREX_VERSION}"; \
      sleep 5; ./trex-console --port "${DUT_TREX_SYNC_SSH_PORT_FORWARDING}" \
      --async_port "${DUT_TREX_ASYNC_SSH_PORT_FORWARDING}"" C-m
  tmux send-keys -t $session_name:1.0 "start -f "${TREX_TRAFFIC_DIR}"/udp_1pkt_tuple_gen.py -m 14mpps -p 0; \
      portattr -a --prom on; tui" C-m
  
  #---------------------------------------------------------#
  #                        PANEL 1                          #
  #---------------------------------------------------------#
  tmux send-keys -t $session_name:1.1 ""${dirname}"/install_trex_remote.sh" C-m
  tmux send-keys -t $session_name:1.1 ""${dirname}"/deploy_trex_config.sh" C-m
  tmux send-keys -t $session_name:1.1 ""${dirname}"/run_trex_server.sh" C-m

  #tmux send-keys -t $session_name:1.1 "ssh "${TREX_SERVER_NAME}"" C-m
}


create_window_upf(){
  tmux rename-window -t 0 'UPF'    
  
  configure_layout $session_name 0 0 -h
  configure_layout $session_name 0 1 -v
  configure_layout $session_name 0 0 -v
  #resize_panel $session_name 0 0 -L 10 
  send_keys_upf
}


create_window_trex() {
  tmux new-window -d -t $session_name -n 'Trex'
  configure_layout $session_name 1 0 -h
  resize_panel $session_name 1 0 -R 10
  send_keys_trex
}




attach() {
  echo "Attaching on session "${session_name}"..."
  tmux select-pane -t $session_name:0.0
  tmux -2 attach-session -t $session_name
}

stop() {
  echo "Stopping on session "${session_name}"..."
}

force_kill() {
  echo "Killing on session "${session_name}"..."
  sleep 2
  tmux kill-session -t $session_name 2>/dev/null
}


main() {
  # set -o errexit
  set -o pipefail
  set -o nounset
  # set -x

  local -r dirname="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local -r filename="${dirname}/$(basename "${BASH_SOURCE[0]}")"
  local -r session_name="test"

  source "${dirname}"/../env.sh
  
#   echo -n "Enter the server admin password:"
#   echo
#   read -s SERVER_PASSWORD

  unset TMUX

  echo "Creating test session: "${session_name}"..."
  tmux kill-session -t $session_name -n testbed 2>/dev/null
  tmux -2 new-session -d -s $session_name 
  
  create_window_upf
  #remove_trex
  create_window_trex
  attach
  stop
  force_kill
}

main "$@"