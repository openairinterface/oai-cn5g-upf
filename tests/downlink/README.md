# HOWTO
Please perform the following actions in order of apparition:
## 1. Setup for Downlink

|             +-----------+                    |        |                          +-----------+              | 
|             |           |+(n6, enp7s0)----------------+-----------------(enp7s0)+|           |              |
+----(enp1s0)+|    UPF    |                    |        |                          | DN (Trex) |+(enp1s0)-----+
|             |           |+(n3, enp6s0)-------+--------------------------(enp6s0)+|           |              |
|             +-----------+                    |        |                          +-----------+              |
|                                              |        |                                                     |s-mngt                                        s-sgi    s-s1                                                s-mngt

### 1.1 UPF Configuration

#### a. Add route
Add a route to reach the gNB (which in our setup is the KVM bridge subnet-sgi):
```bash
sudo ip route del 192.168.128.0/23
sudo ip route add 192.168.128.0/23 via 192.168.60.5 dev enp6s0
```

#### b. Ifconfig
```bash
$ifconfig
enp1s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.100.4  netmask 255.255.255.0  broadcast 192.168.100.255
        ether 52:54:00:af:c5:87  txqueuelen 1000  (Ethernet)
        RX packets 26293631  bytes 5248289205 (5.2 GB)
        RX errors 0  dropped 6  overruns 0  frame 0
        TX packets 21948833  bytes 343362497926 (343.3 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp6s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.60.4  netmask 255.255.255.0  broadcast 192.168.60.255
        ether 52:54:00:3c:55:00  txqueuelen 1000  (Ethernet)
        RX packets 80939  bytes 4230574 (4.2 MB)
        RX errors 0  dropped 6  overruns 0  frame 0
        TX packets 357  bytes 29684 (29.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp7s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.128.4  netmask 255.255.254.0  broadcast 192.168.129.255
        ether 52:54:00:a5:ab:33  txqueuelen 1000  (Ethernet)
        RX packets 81263  bytes 4244603 (4.2 MB)
        RX errors 0  dropped 6  overruns 0  frame 0
        TX packets 68  bytes 4424 (4.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 8525796  bytes 341726386559 (341.7 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 8525796  bytes 341726386559 (341.7 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

#### c. Ip Route
```bash
$ip r
default via 192.168.100.1 dev enp1s0 proto static 
192.168.60.0/24 dev enp6s0 proto kernel scope link src 192.168.60.4 
192.168.100.0/24 dev enp1s0 proto kernel scope link src 192.168.100.4 
192.168.128.0/23 via 192.168.60.5 dev enp6s0
```



### 1.2 DN Configuration

#### a. Add route
Add a route to reach the gNB via UPF:
```bash
sudo ip route del 192.168.60.0/24
sudo ip route add 192.168.60.0/24 via 192.168.128.4 dev enp7s0
```

#### b. Ifconfig
```bash
$ifconfig
enp1s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.100.5  netmask 255.255.255.0  broadcast 192.168.100.255
        inet6 fe80::5054:ff:fea1:7036  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:a1:70:36  txqueuelen 1000  (Ethernet)
        RX packets 563988  bytes 57781145 (57.7 MB)
        RX errors 0  dropped 5  overruns 0  frame 0
        TX packets 478518  bytes 6550347422 (6.5 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp6s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.60.5  netmask 255.255.255.0  broadcast 192.168.60.255
        inet6 fe80::5054:ff:fe5d:1a93  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:5d:1a:93  txqueuelen 1000  (Ethernet)
        RX packets 80560  bytes 4210706 (4.2 MB)
        RX errors 0  dropped 5  overruns 0  frame 0
        TX packets 60  bytes 4296 (4.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp7s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.128.5  netmask 255.255.254.0  broadcast 192.168.129.255
        inet6 fe80::5054:ff:fea8:1372  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:a8:13:72  txqueuelen 1000  (Ethernet)
        RX packets 80583  bytes 4211679 (4.2 MB)
        RX errors 0  dropped 5  overruns 0  frame 0
        TX packets 390  bytes 18570 (18.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 225424  bytes 6518658133 (6.5 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 225424  bytes 6518658133 (6.5 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

#### c. Ip Route
```bash
$ip r
default via 192.168.100.1 dev enp1s0 proto static 
192.168.60.0/24 via 192.168.128.4 dev enp7s0 
192.168.100.0/24 dev enp1s0 proto kernel scope link src 192.168.100.5 
192.168.128.0/23 dev enp7s0 proto kernel scope link src 192.168.128.5 
```


## 2. Run UPF Application
After the configuration of the setup, you can run the application
```bash
$sudo upf -o -c etc/upf.conf
```


## 3. Create a PFCP request for downlink
Please the file `create_session_downlink.yaml` that you have to run from `pfcp-kitchen-sink`


## 4. Create ARP Table
After the PFCP session request creation, you have to create an ARP table for the UPF to use as the forwarding is done on the next hop. For that please run the script `create_arp_table_downlink.sh`
```bash
$./create_arp_table_downlink.sh
```

## 5. Generate downlink traffic
From your DN VM, generate traffic with `scapy` using the python script `generate_traffic_downlink.py`
