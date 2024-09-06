#!/bin/sh

tmux kill-session -t test
sudo ip link set dev enp5s0f0 xdp off 
sudo ip link set dev enp5s0f1 xdp off

sudo ethtool -s enp5s0f0 speed 10000 duplex full autoneg off
sudo ethtool -s enp5s0f1 speed 10000 duplex full autoneg off

sudo su 
sudo echo 1 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/tracing_on
exit