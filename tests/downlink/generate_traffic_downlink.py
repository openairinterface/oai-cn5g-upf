# Run this script from the host
cd ~/workspace/upf-project/scapy/ && sudo ./run_scapy
>> sendp(Ether()/
    IP(src="192.168.128.5",dst="192.168.60.1")/
    UDP(dport=1234)/Raw(load="OpenAirInterface"), iface="enp7s0",count=10)