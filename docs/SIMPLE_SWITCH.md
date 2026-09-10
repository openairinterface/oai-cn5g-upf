<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# The Simple Switch UPF

## 1. What it is

The simple switch is one of the two user-plane datapaths in this UPF. It moves
subscriber traffic using ordinary Linux networking: UDP sockets for GTP-U on
N3, and a `tun` device for plain IP on N6. It is a normal user-space program.
It loads nothing into the kernel.

Everything it needs from the kernel it asks for through standard interfaces:
sockets, `tun`, netlink, and `tc`. That means it runs in places where loading
programs into the kernel is not allowed, and it needs no special privileges
beyond `CAP_NET_ADMIN` and access to `tun` device. 

## 2. Which datapath to use

| | **Simple switch** | **eBPF / XDP datapath** |
| --- | --- | --- |
| Where packets are handled | user space | in the kernel, at the driver hook |
| Loads programs into the kernel | no | yes |
| Needs a dedicated IP per interface | no | yes, on N3, N6 and N4 |
| Container network mode | normal (bridge) | host mode |
| Throughput | good | higher |

To know more about the eBPF UPF check the [features](./FEATURE_SET.md) 

To select simple switch (user space) UPF in the configuration file enable `enable_bpf_datapath: no`.

## 3. Interfaces

| **Name** | **What it carries** | **How it is implemented** |
| --- | --- | --- |
| N3 | GTP-U tunnels to and from the gNB | UDP socket on port 2152 |
| N4 | PFCP signalling with the SMF | UDP socket on port 8805 |
| N6 | plain IP to and from the data network | `tun0` device plus normal routing |

## 4. How a packet travels

**Uplink — from the UE to the internet**

1. A GTP-U packet arrives on the N3 socket. Several threads read that socket;
   whichever is free takes it.
2. The UPF reads the TEID from the GTP-U header and looks up the matching
   uplink PDR.
3. The rules on that PDR say what to do. Normally: remove the GTP-U header
   (the FAR's *outer header removal*) and forward.
4. The inner IP packet is written to `tun0`. From there the host routes it to
   the data network like any other packet.

**Downlink — from the internet to the UE**

1. A plain IP packet arrives on `tun0`. Several threads read that device;
   whichever is free takes it.
2. The UPF looks up the destination address, which is the UE's address, and
   finds the downlink PDR.
3. The FAR carries an *outer header creation*: the gNB's address and the TEID
   to use.
4. The UPF writes a GTP-U header in front of the packet and sends it out of the
   N3 socket. The buffer has space reserved in front for exactly this, so no
   copy is needed.

Transmits are grouped: up to 16 packets are handed to the kernel in one
`sendmmsg()` call instead of one call each.

## 5. Inside: the threads

| **Thread** | **Job** |
| --- | --- |
| N3 receive (`n3_rx_threads` of them) | read GTP-U, decapsulate, write to `tun0` |
| N6 receive (`dl_rx_queues` of them) | read own `tun0` queue, encapsulate, send GTP-U |
| N4 | PFCP: associations, sessions, reports |
| ITTI tasks (app, timer, async) | control-plane message passing and timers |
| usage report | wakes every 30 seconds and sends usage reports |

A receive thread does the whole job for its packet: read, look up, forward.
There is no queue between a reader and a worker. An earlier design passed
packets between threads through a queue, and that cost a sleep and a wake per
packet, which was more expensive than the forwarding itself.

Reads are batched: on N3 one `recvmmsg()` call collects up to 16 datagrams; on
N6 the `tun` queue is drained with one non-blocking `read()` per packet until
it returns `EAGAIN`.

## 6. Spreading work over CPUs

**A flow must be handled by one thread, or it arrives out of order.**

Each N6 receive thread owns its own `tun` queue (`IFF_MULTI_QUEUE`). The kernel
hashes each packet's flow and always puts a given flow in the same queue, so
the thread that owns that queue is the only one that ever sees the flow. A
packet cannot overtake another packet of the same flow, because there is no
second thread to overtake it with.

**The uplink write side picks the queue too, and must use the same rule.** When
the UPF writes an uplink packet into `tun`, the kernel records `flow -> that
queue` and steers the *downlink* of the same flow to it. So `send_to_core()`
chooses the queue by hashing the inner flow, not by thread: a per-thread choice
makes the mapping flap and the reordering comes back through the write side.

Two consequences worth knowing:

* **One flow gets one queue, so one core.** A single TCP connection cannot be
  spread over CPUs by any design that keeps it in order. Several connections
  from one UE do spread, because the hash is over the 5-tuple, not the UE.
* **The split is statistical.** With a handful of flows two can land on the same
  queue while another thread sits idle. The per-queue counters logged every ten
  seconds (`tun queue balance`, debug level) exist so this is recognizable
  instead of looking like a throughput ceiling.

The N3 uplink still has all receive threads on **one shared socket**, so it has
no ordering guarantee: two threads can take consecutive datagrams and write
them to `tun` in either order. That is a property of the load, not
a guarantee: more gNBs, higher rates or slower per-packet work could expose it.

The downlink fix does not transfer. `SO_REUSEPORT` picks a socket by hashing
the outer addresses and ports, and every GTP-U packet from one gNB carries the
same outer 4-tuple, so it would put one gNB on one thread regardless of how
many PDU sessions it carries. Steering by TEID needs either a per-packet
handoff between threads or a BPF program on the socket. Until one of those
exists, treat `n3_rx_threads` above 1 as unverified for ordering rather than
known-safe.

## 7. A CPU kept for the control plane

The receive threads run at real-time priority. If they are allowed on every CPU
the container/UPF host has, then at full load they starve the N4 thread. 
The UPF then stops answering PFCP heartbeats, 
and the SMF concludes the UPF is dead and 
removes the association — bringing down every session with it.

So the UPF reserves the lowest-numbered CPU of its own cpuset for the control
plane. This is whichever CPU the operator gave it first, not the machine's
CPU 0. The N4, ITTI and application threads are pinned there. The receive
threads are pinned to the remaining CPUs, one each.

**Give the container one more CPU than the number of receive threads.** With
`n3_rx_threads: 4` and `dl_rx_queues: 4`, give it five. If you give it exactly
four, the UPF still reserves one and warns that the datapath threads now have
to share.

## 8. Session tables

Three tables are read on the packet path:

| **Table** | **Key** | **Used by** |
| --- | --- | --- |
| uplink PDRs | GTP-U TEID | uplink |
| downlink PDRs | UE IPv4 address | downlink |
| sessions | UP SEID | reporting and teardown |

They use `upf_map`, a hash map whose readers never take a lock. Writers (PFCP
session create, modify, delete) publish a new version and free the old one once
every reader has moved on. This is the pattern in `upf_rcu.hpp`. Only the N4
thread writes, so writes are already serialised.

## 9. QoS: enforcing a rate limit

When the SMF sends a QER with a Maximum Bitrate, the UPF installs a filter with
the kernel's own traffic control:

```
tc qdisc add dev <N3> clsact
tc filter add dev <N3> egress protocol ip prio <p> u32 \
   match ip protocol 17 0xff match ip dport 2152 0xffff \
   match u32 <TEID> 0xffffffff at 32 \
   action police rate <MBR>bit burst <10 ms> mtu 64kb conform-exceed drop
```

One filter per TEID per direction: uplink on `ingress`, downlink on `egress`.
The TEID sits at a fixed offset — 20 bytes of IPv4 plus 8 of UDP plus 4 of
GTP-U — so a plain `u32` match finds it. No program is loaded; this is standard
`tc`, set up over netlink.

**It polices, it does not shape.** Traffic above the rate is dropped, not
delayed. Shaping would need a queueing discipline on the interface root, and
the UPF transmits from a veth with a single transmit queue, so any root
queueing discipline puts every transmit thread behind one lock. Both HTB and
EDT pacing with `fq` were measured, and both cost about a third of the
throughput. 3GPP TS 29.244 §8.2.8 makes the MBR a limit rather than a smoothing
requirement, so dropping the excess is the correct behaviour.

Nothing is installed until a session actually has a rate. A deployment with no
QoS keeps a bare interface with no `tc` filters at all.

If a Session Modification arrives with the same rate, the filter is left alone
so it keeps its credit. Modifications arrive on every handover and must not
reset a limiter that did not change.

## 10. Usage reporting

Each session counts uplink and downlink octets and packets as it forwards them.
The counters are plain atomics, updated with relaxed ordering, because the
reporting thread wants a recent total, not a precise instant.

Every 30 seconds the reporting thread walks the session table and sends a PFCP
Session Report Request for each session that moved traffic. The report carries:

* Report Type = usage report
* URR ID, and a sequence number that increases with every report
* Volume Measurement: total, uplink and downlink, in both octets and packets
* Duration Measurement

**Reports carry the difference since the last report, not a running total.**
The SMF adds them up. A difference stays correct if either side restarts;
a running total does not.

A final report is sent when the session is deleted, so the last interval is not
lost.

Turn it on with `enable_urr: yes`.

## 11. Configuration

| **Setting** | **Meaning** | **Default** |
| --- | --- | --- |
| `enable_bpf_datapath` | `no` selects the simple switch | — |
| `n3_rx_threads` | threads sharing the N3 socket (uplink) | 1 |
| `dl_rx_queues` | `tun0` queues, one thread each (downlink) | 1 |
| `enable_qos` | enforce QER Maximum Bitrate | — |
| `enable_urr` | measure volume and send usage reports | — |

Sizing rules:

* Start with 1 thread per direction. That is about 2.8 Gbps each way, and one
  flow never exceeds that no matter how many queues you configure: a flow is
  pinned to one queue so that it cannot be reordered, and one queue is one
  thread on one core.
* Give the container **`n3_rx_threads` + `dl_rx_queues` + 1** CPUs. The uplink
  and downlink pools are placed on different cores, and the spare one is for
  the control plane. Short of that the UPF logs `datapath threads now share
  cores` and pins two datapath threads to the same CPU.
* **Set `dl_rx_queues` above the number of concurrent flows you care about,
  not equal to it.** Queues are hash buckets. 
* Watch the `tun queue balance` line (debug level, every ten seconds). It
  prints per-queue packet counts, which is how you tell an unlucky hash from a
  genuine ceiling.

## 12. Measured performance

On an NVIDIA Grace (Neoverse-V2), UDP, 1400-byte payloads, four gNBs, four PDU
sessions, four receive threads per direction plus one CPU for the control
plane:

| **Direction** | **Total** | **Per session** |
| --- | --- | --- |
| Downlink | 8.8 Gbps | 2.20 Gbps × 4 |
| Uplink | 9.2 Gbps | 2.30 Gbps × 4 |

With one thread per direction, roughly 3 Gbps each way (1 gNB and 4 UEs).

TCP, same machine, eight queues on eight datapath cores, one gnbsim container
per UE:

| **UEs** | **Aggregate** | **Per UE** | **Scaling** |
| --- | --- | --- | --- |
| 1 | 2.73 Gbps | 2730 Mbps | — |
| 2 | 5.51 Gbps | 2710-2800 Mbps | 2.02x |
| 4 | 10.17 Gbps | 2520-2570 Mbps | 3.73x |
| 8 | 12.86 Gbps | 1390-1790 Mbps | 4.71x |

Near-linear to four UEs, then it flattens as the cores fill (652% of the 800%
available at eight UEs). Note the load generator: one gnbsim container caps at
about 2.6 Gbps regardless of how many UEs are behind it, so four UEs inside a
single gnbsim measured 2.60 Gbps with the UPF only 31% busy. Use one gnbsim
container per UE, and one DN container per UE.

Two things move these numbers a lot:

* **The UE MTU.** A 1500-byte inner packet does not fit inside GTP-U on a
  1500-byte N3 link, so every full-size TCP segment is fragmented and TCP
  throughput roughly halves. Set `ue_mtu` to 1456 or less in the SMF. The SMF
  signals it to the UE in the PDU Session Establishment Accept.
* **The number of CPUs**, as described above.

## 13. Host tuning: what actually matters

The simple switch is not a poll-mode datapath. Its threads block in
`recvmmsg()` and `read()` and are woken by the kernel when a packet arrives.
:

|      **Kernel option**       |
| ---------------------------- |
| `processor.max_cstate=0`     |
| `irqaffinity=<control cpus>` |
| `numa_balancing=disable`     |

Configure the CPU governor to performance and disable cpu clock speed. 

What matters far more than any of these: the container's cpuset, one CPU
reserved for the control plane, and the UE MTU.

## 14. What it does not do

* It does not load any program into the kernel.
* It does not shape traffic; it polices (see section 9).
* The datapath is IPv4 today. IPv6 addresses can be configured on `tun0`, but
  the forwarding path and the QoS filters handle IPv4.
* The QoS filter list is linear. It is fine for tens of sessions. Many more
  than that will need `u32` hash tables so the lookup stays constant-time.
