<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# The Simple Switch UPF

## 1. What it is

The simple switch is one of the two user-plane datapaths in this UPF. It moves
subscriber traffic with ordinary Linux networking: UDP sockets for GTP-U on N3,
and a `tun` device for plain IP on N6. It is a normal user-space program and
loads nothing into the kernel, so it runs where loading kernel programs is not
allowed. It needs `CAP_NET_ADMIN` and `/dev/net/tun`, not privileged mode.

Select it with `enable_bpf_datapath: no`.

| | **Simple switch** | **eBPF / XDP datapath** |
| --- | --- | --- |
| Where packets are handled | user space | kernel, at the driver hook |
| Loads programs into the kernel | no | yes |
| Needs a dedicated IP per interface | no | yes, on N3, N6 and N4 |
| Container network mode | normal (bridge) | host mode |
| Throughput per core | lower | higher |

## 2. Interfaces

| **Name** | **What it carries** | **How** |
| --- | --- | --- |
| N3 | GTP-U to and from the gNB | UDP socket on port 2152 |
| N4 | PFCP with the SMF | UDP socket on port 8805 |
| N6 | plain IP to and from the data network | `tun0` plus normal routing |

## 3. How a packet travels

```
downlink    DN --> tun0 queue q --> [ DL thread q ] --> N3 socket q --> gNB
                                    match PDR, FAR, GTP-U encapsulate

uplink     gNB --> N3 socket q --> [ UL thread q ] --> tun0 queue q --> DN
                                   decapsulate, match PDR, FAR
```

One thread does the whole job for its packet: read, look up, forward. There is
no queue and no hand-off between threads.

Four properties follow from that, and they are what you configure against:

* **A flow is pinned to one queue, and a queue to one thread.** That is what
  keeps a flow in order, and it also means a single flow never exceeds what one
  core can do, however many queues are configured.
* **Each direction has its own pool.** `n3_rx_threads` threads read N3 and
  write `tun0`; `dl_rx_queues` threads read `tun0` and write N3. A downlink
  packet never touches an uplink thread, so uplink thread *i* and downlink
  thread *i* are pinned to the same core.
* **N3 sockets are an `SO_REUSEPORT` group**, one per uplink thread, and the
  kernel hashes on the outer addresses. All of one gNB's traffic therefore
  lands on one socket and one thread; size `n3_rx_threads` against the number
  of gNBs, not the number of sessions.
* **Downlink queue choice belongs to the kernel**, which hashes the inner flow
  across the `tun0` queues. Set `dl_rx_queues` above the number of concurrent
  flows you care about, not equal to it: queues are hash buckets, and with as
  many buckets as flows, collisions leave cores idle.

Reads and writes are batched — one `recvmmsg()` or `sendmmsg()` carries up to
64 packets. `tun0` is opened with `IFF_VNET_HDR` and TSO, so the kernel hands
over TCP in super-packets of up to 64 kB and the UPF splits them itself rather
than paying a syscall per segment. Session lookups are lock-free on the read
side; only the N4 thread writes.

## 4. QoS and usage reporting

When a QER carries a Maximum Bitrate, the UPF meters the flow in user space
against two rates: the QoS flow's own MBR, and one shared per session and
direction for the session AMBR (3GPP TS 29.244 §8.2.8). Turn it on with
`enable_qos: yes`.

The meter is a departure clock, so the same state answers both "may I send
this?" and "when may I send this?", and one setting picks which:

* `qos_shape_ms: 0` **polices** — a packet over rate is dropped, and
  `qos_burst_ms` is the burst forgiven first.
* `qos_shape_ms: N` **shapes** — a packet over rate waits for its slot, for at
  most N ms, and is dropped only if its slot is further out than that.

`qos_shape_ms` is the downlink and `qos_shape_ul_ms` the uplink, separately,
because they are not the same problem. The uplink defaults to policing: by the
time a packet reaches the UPF the radio has already been spent, so holding it
relieves nothing and only hides the loss from the sender.

Shaping costs a copy and a buffer for each packet it holds, and nothing at all
for traffic inside its rate. It is worth it for TCP: at an MBR well under line
rate and a 20 ms allowance, a policed flow settles around a tenth of its MBR
because the drops keep collapsing the congestion window, while a shaped one
holds about 97% of it, in either direction. With a large allowance (say 400 ms
of burst) a policer rarely bites and the two behave alike.

**Do not shape a session that carries delay-critical traffic.** A packet inside
its rate is never queued, so it is unaffected — but one that shares the session
AMBR with a flow saturating it inherits that queue: measured through this UPF,
a ping alongside a bulk flow goes from 33 µs when policing to 19.8 ms with a
20 ms shaper. The session AMBR is one clock for the whole session, and it does
not yet exclude GBR flows the way TS 23.501 §5.7.2.6 requires.

Each downlink thread holds its own queue, 1024 packets, and that slab is the
hard ceiling behind the time horizon: with `qos_shape_ms` set so high that the
queue would need more, the extra is dropped on arrival rather than admitted.
The queue's depth, what it has held and dropped, and how late it has been all
appear on the `tun queue balance` debug line.

With `enable_urr: yes` a thread walks the session table every 30 seconds and
sends a PFCP Session Report Request for each session that moved traffic, with
volume and duration *since the last report*, plus a final report at session
deletion.

## 5. Configuration

| **Setting** | **Meaning** | **Default** |
| --- | --- | --- |
| `enable_bpf_datapath` | `no` selects the simple switch | — |
| `n3_rx_threads` | uplink threads, one N3 socket each | 1 |
| `dl_rx_queues` | `tun0` queues, one downlink thread each | 1 |
| `enable_qos` | enforce QER Maximum Bitrate | — |
| `enable_urr` | measure volume and send usage reports | — |
| `qos_burst_ms` | burst forgiven before the policer drops, in ms of rate | 400 |
| `qos_shape_ms` | 0 polices the downlink; above 0 shapes it, holding a packet at most this long | 0 |
| `qos_shape_ul_ms` | the same for the uplink | 0 |

Start with one thread per direction and raise both together.

## 6. Host setup

**Give the container max(`n3_rx_threads`, `dl_rx_queues`) + 1 CPUs**, as a
`cpuset`. The spare one is for the control plane: datapath threads run at
real-time priority, and without a CPU of its own the N4 thread stops answering
PFCP heartbeats under load, after which the SMF tears the association down. The
UPF reserves the lowest-numbered CPU of its cpuset for that and pins each
datapath thread to one of the rest. It warns if it has to put two threads of
one direction on a CPU.

**Leave room for the GTP-U header.** The UPF adds 44 bytes — outer IP 20, UDP
8, GTP-U with the PDU Session Container 16. If the N3 link is 1500 and the UE
sends 1500-byte packets, every one of them is fragmented and the packet rate
doubles. Either provision N3 above 1544 — 1600 is the usual choice — or keep
the UE's MTU at 1456 or below, which is the SMF's `ue_mtu` (default 1400, sent
to the UE in the PCO). A UE that ignores it, as some simulators do, needs the
larger N3. Verify rather than assume: `FragOKs` in `/proc/<upf pid>/net/snmp`
must stay flat while traffic runs.

**Fix the clock.** The per-packet path is a roughly fixed number of cycles, so
throughput per queue scales with core frequency almost linearly — the same core
at 2 GHz carries about two thirds of what it carries at 3 GHz. Set the governor
to `performance`, and keep the cores out of deep idle states, which otherwise
cost wake-up latency on every batch:

```
cpupower frequency-set -g performance
# kernel cmdline
processor.max_cstate=1 intel_idle.max_cstate=0
```

**Isolated CPUs are not required.** A cpuset is what matters; `isolcpus` only
adds the guarantee that nothing else is scheduled on those cores, which is
worth having on a busy host and does nothing on a quiet one. If you do use it,
note that `isolcpus=domain` also stops the kernel load-balancing *within* the
set: anything pinned there must place its own threads. The UPF does, with
`pthread_setaffinity_np()`. Load generators frequently do not, and then pile
onto the first CPU of their cpuset while the rest idle — which looks exactly
like a UPF ceiling and is not one. Give each such container a narrow cpuset and
`taskset` its processes explicitly.

**TCP congestion control is not a UPF setting.** The endpoints are the UE and
the server; the UPF only forwards, and needs nothing from BBR or from CUBIC. If
the MTU and CPU budget above are right, TCP crosses the UPF without loss and
the default CUBIC is fine. BBR at the endpoints only changes what happens when
the UPF is deliberately driven past its capacity, where it holds throughput
that CUBIC gives up — that is a property of the sender, not something to
configure here.

## 7. What it does not do

* It does not load any program into the kernel.
* It polices, it does not shape.
* The datapath is IPv4. IPv6 can be configured on `tun0`, but forwarding and
  the rate meters handle IPv4.
* It splits IPv4 TCP super-packets only. Anything else is forwarded whole if it
  fits a buffer, and dropped with a warning if it does not.
* It does not coalesce on the uplink: packets arrive one at a time and are
  written to `tun0` one `writev()` each.
