## Prerequisites

To use this application, make sure you have the following installed:
- Docker
- Docker Compose
- pfcp-kitchen-sink (https://github.com/infinitydon/pfcp-kitchen-sink.git)
- OAI-UPF
- Scapy for generating traffic

## Set up

Follow these instructions to set up the environment:

1. Install pfcp-kitchen-sink:
```bash
git clone https://github.com/infinitydon/pfcp-kitchen-sink.git
cd pfcp-kitchen-sink

go get  github.com/alvaroloes/enumer
go generate ./pkg/pfcp
```

2. Install scapy:
```bash
pip install scapy
```

## Run

To run the application, follow these steps:

1. Start the UPF and gateway using Docker Compose:
```bash
docker compose -f assets/docker-compose-kitchen.yml up -d
```

2. Start pfcp-kitchen-sink to install session rules:
```bash
./pfcpclient -r 192.168.70.134:8805 -s assets/sessions.yaml
```

## Generate Traffic for Testing

Use this Python script with Scapy library to generate traffic for testing. Note that `vethbcccbfd` is the veth pair for the UPF container n3 interface:
```python
from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer
from scapy.all import *

sendp(Ether(dst="02:42:c0:a8:46:86")/
    IP(src="192.168.70.1",dst="192.168.70.134")/
    UDP(dport=2152)/GTP_U_Header(teid=1234)/ 
    GTPPDUSessionContainer(type=1, QFI=5)/ 
    IP(src="12.1.1.1",dst="8.8.8.8",version=4)/
    ICMP(), iface="vethbcccbfd", count=10)
```