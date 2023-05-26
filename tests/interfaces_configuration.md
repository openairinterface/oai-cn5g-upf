### 1. Trex Network Configuration
```
$ ifconfig
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:f6:cc:3d:66  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp1s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.100.5  netmask 255.255.255.0  broadcast 192.168.100.255
        inet6 fe80::5054:ff:fea1:7036  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:a1:70:36  txqueuelen 1000  (Ethernet)
        RX packets 49  bytes 7975 (7.9 KB)
        RX errors 0  dropped 3  overruns 0  frame 0
        TX packets 40  bytes 6565 (6.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp6s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.60.5  netmask 255.255.255.0  broadcast 192.168.60.255
        inet6 fe80::5054:ff:fe5d:1a93  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:5d:1a:93  txqueuelen 1000  (Ethernet)
        RX packets 26  bytes 1352 (1.3 KB)
        RX errors 0  dropped 21  overruns 0  frame 0
        TX packets 7  bytes 586 (586.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp7s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.128.5  netmask 255.255.254.0  broadcast 192.168.129.255
        inet6 fe80::5054:ff:fea8:1372  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:a8:13:72  txqueuelen 1000  (Ethernet)
        RX packets 28  bytes 1446 (1.4 KB)
        RX errors 0  dropped 22  overruns 0  frame 0
        TX packets 7  bytes 586 (586.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 80  bytes 5920 (5.9 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 80  bytes 5920 (5.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

### 2. UPF-ebpf Network Configuration
```
$ ifconfig
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:5a:02:b4:33  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp1s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.100.4  netmask 255.255.255.0  broadcast 192.168.100.255
        inet6 fe80::5054:ff:feaf:c587  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:af:c5:87  txqueuelen 1000  (Ethernet)
        RX packets 128  bytes 12535 (12.5 KB)
        RX errors 0  dropped 49  overruns 0  frame 0
        TX packets 52  bytes 8457 (8.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp6s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.60.4  netmask 255.255.255.0  broadcast 192.168.60.255
        inet6 fe80::5054:ff:fe3c:5500  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:3c:55:00  txqueuelen 1000  (Ethernet)
        RX packets 61  bytes 3448 (3.4 KB)
        RX errors 0  dropped 49  overruns 0  frame 0
        TX packets 6  bytes 516 (516.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp7s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.128.4  netmask 255.255.254.0  broadcast 192.168.129.255
        inet6 fe80::5054:ff:fea5:ab33  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:a5:ab:33  txqueuelen 1000  (Ethernet)
        RX packets 61  bytes 3448 (3.4 KB)
        RX errors 0  dropped 49  overruns 0  frame 0
        TX packets 7  bytes 586 (586.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 240  bytes 17760 (17.7 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 240  bytes 17760 (17.7 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```