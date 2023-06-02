# Run this script from the host
cd ~/workspace/upf-project/scapy/ && sudo ./run_scapy
from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer
sendp(Ether(dst="52:54:00:3c:55:00")/
                    IP(src="192.168.60.1",dst="192.168.60.4")/
                    UDP(dport=2152)/GTP_U_Header(teid=100)/ 
                    IP(src="192.168.60.1",dst="192.168.128.5",version=4)/ 
                    ICMP(), iface="subnet-sgi", count=5)