#!/bin/bash
# SPDX-License-Identifier: MIT
set -eo pipefail


######################################################################################################
# Function to check if BPF datapath is enabled
######################################################################################################
check_enable_bpf_datapath() {
  enable_bpf_datapath=$(cat /openair-upf/etc/*.yaml | grep "enable_bpf_datapath:" | awk '{print $2}')
    
    # Check if bpf_datapath is set to yes
  if [ "$enable_bpf_datapath" == "yes" ]; then
    return 0  # BPF Datapath is enabled
  else
    return 1  # BPF Datapath is not enabled
  fi
}


######################################################################################################
# Function to check if BPF QoS enforcement datapath is enabled
######################################################################################################
check_enable_qos() {
  enable_qos=$(cat /openair-upf/etc/*.yaml | grep -A 3 "upf:" | grep "enable_qos:" | awk '{print $2}')

  # Check if enable_qos is set to yes
  if [[ "$enable_qos" == "yes" ]]; then
    return 0  # QoS is enabled
  else
    return 1  # QoS is not enabled
  fi
}


######################################################################################################
# Function to retrieve interface from config file
######################################################################################################
get_interface_name() {
  local reference_point=$1
  
  # Extract the interface name for the given reference point (n3, n4, n6, etc.) under UPF
  interface_name=$(cat /openair-upf/etc/*.yaml | grep -A 16 "upf:" | awk -v ref="$reference_point:" '
  $0 ~ ref {found=1} 
  found && /interface_name:/ {print $2; exit}
  ')

  if [[ -z "$interface_name" ]]; then
    echo "Error: interface_name not found for reference point $reference_point."
    return 1
  fi

  echo "$interface_name"
}


######################################################################################################
# Function to check if the configuration file is properly set
######################################################################################################
check_configuration_file() {
  NB_UNREPLACED_AT=$(cat /openair-upf/etc/*.yaml | grep -v contact@openairinterface.org | grep -c @ || true)

  if [ $NB_UNREPLACED_AT -ne 0 ]; then
    echo "Healthcheck error: UNHEALTHY configuration file is not configured properly"
    return 1
  fi
}

######################################################################################################
# Function to check if the N3 XDP program <xdp_handle_uplink> properly attached
######################################################################################################
check_n3_xdp_program() {
  local interface_name="$1"
  # Retrieve the XDP program ID associated with the n3 interface
  XDP_PROGRAM_ID=$(ip link show dev $interface_name | grep -oP 'prog/xdp id \K\d+')
  
  if [[ -z "$XDP_PROGRAM_ID" ]]; then
    echo "Healthcheck error: XDP program ID not found for $interface_name interface."
    return 1
  fi

  # Retrieve the program name associated with the XDP program ID from bpftool
  XDP_PROGRAM_NAME=$(/openair-upf/bin/bpftool prog list | grep -w "$XDP_PROGRAM_ID" | awk '{print $4}')

   if [[ -z "$XDP_PROGRAM_NAME" ]]; then
    echo "Healthcheck error: XDP program name not found for $interface_name interface."
    return 1
  fi
	
  if [[ "$XDP_PROGRAM_NAME" == "xdp_handle_uplink" ]]; then
    echo "xdp_handle_uplink program is correctly linked to $interface_name interface."
  else
    echo "Healthcheck error: xdp_handle_uplink program not linked to $interface_name interface. Found $XDP_PROGRAM_NAME instead."
    return 1
  fi
}


######################################################################################################
# Function to check if the N6 XDP program <xdp_handle_downlink> or <xdp_handle_shaping> properly attached
######################################################################################################
check_n6_xdp_program() {
  local interface_name="$1"
  # Retrieve the XDP program ID associated with the n6 interface
  XDP_PROGRAM_ID=$(ip link show dev $interface_name | grep -oP 'prog/xdp id \K\d+')
  
  if [[ -z "$XDP_PROGRAM_ID" ]]; then
    echo "Healthcheck error: XDP program ID not found for $interface_name interface."
    return 1
  fi

  # Retrieve the program name associated with the XDP program ID from bpftool
  XDP_PROGRAM_NAME=$(/openair-upf/bin/bpftool prog list | grep -w "$XDP_PROGRAM_ID" | awk '{print $4}')

   if [[ -z "$XDP_PROGRAM_NAME" ]]; then
    echo "Healthcheck error: XDP program name not found for interface_name interface."
    return 1
  fi
	
  # Check if QoS is enabled
  if check_enable_qos; then
    # If QoS is enabled, check if the program name is xdp_handle_shaping
    if [[ "$XDP_PROGRAM_NAME" == "xdp_handle_shaping" ]]; then
      echo "xdp_handle_shaping program is correctly linked to $interface_name interface."
    else
      echo "Healthcheck error: xdp_handle_shaping program not linked to $interface_name interface. Found $XDP_PROGRAM_NAME instead."
      return 1
    fi
  else
    # If QoS is not enabled, check if the program name is xdp_handle_downlink
    if [[ "$XDP_PROGRAM_NAME" == "xdp_handle_downlink" ]]; then
      echo "xdp_handle_downlink program is correctly linked to $interface_name interface."
    else
      echo "Healthcheck error: xdp_handle_downlink program not linked to $interface_name interface. Found $XDP_PROGRAM_NAME instead."
      return 1
    fi
  fi
}



######################################################################################################
# Function to check port status
######################################################################################################
check_port_status() {
  local interface_name=$1
  local port=$2
  local ip_interface=$(ifconfig $interface_name | grep inet | awk '{print $2}')
  
  if [[ -z "$ip_interface" ]]; then
    echo "Error: Could not retrieve IP address for interface $interface_name."
    return 1
  fi

  # Check if the port is listening on the specified IP interface
  if netstat -unpl | grep -q "$ip_interface:$port"; then
    echo "Port $port is listening on $ip_interface."
    return 0
  else
    echo "Port $port is NOT listening on $ip_interface."
    return 1
  fi
}

######################################################################################################
# Main healthcheck function
######################################################################################################
main() {
  STATUS=0
  N4_PORT=8805

  echo "Retrieving interface names..."
  N3_INTERFACE=$(get_interface_name "n3")
  echo "N3_INTERFACE: $N3_INTERFACE"

  N4_INTERFACE=$(get_interface_name "n4")
  echo "N4_INTERFACE: $N4_INTERFACE"

  N6_INTERFACE=$(get_interface_name "n6")
  echo "N6_INTERFACE: $N6_INTERFACE"

  if check_configuration_file; then 
    echo "Configuration file is OK."
    
    if check_enable_bpf_datapath; then 
      echo "BPF Datapath is enabled."

      echo "Checking N3 XDP program..."
      check_n3_xdp_program "$N3_INTERFACE"
      if [ $? -ne 0 ]; then
        STATUS=1
      fi	

      echo "Checking N6 XDP program..."
      check_n6_xdp_program "$N6_INTERFACE"
      if [ $? -ne 0 ]; then
        STATUS=1
      fi

      echo "Checking N4 Port Status..."
      check_port_status "$N4_INTERFACE" "$N4_PORT"
      if [ $? -ne 0 ]; then
        STATUS=1
      fi
    else
      echo "TODO: Add checking for SPGW-Tiny"
    fi
  else 
    echo "Configuration file check failed."
    STATUS=1
  fi

  echo "Final Status: $STATUS"
  exit $STATUS
}

######################################################################################################
# Run the main function
######################################################################################################


main
