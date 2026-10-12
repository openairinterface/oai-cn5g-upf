# DPDK datapath

Third datapath flavour of the OAI UPF, next to simple-switch and eBPF/XDP. The
UPF takes the N3 and N6 NICs over from the kernel and forwards packets on
dedicated lcores.

**Status: not yet tested on hardware.** Every file compiles, but no packet has
gone through it. Read [What to expect on first run](#what-to-expect-on-first-run)
before debugging.

## Building

DPDK is optional and off by default:

```bash
sudo apt install dpdk-dev libdpdk-dev   # Ubuntu 22.04 ships DPDK 21.11 LTS
make build-dpdk                         # or: build/scripts/build_upf -j -V -b Debug --dpdk
```

Without `--dpdk` nothing changes: the DPDK sources are not compiled and a
configuration that asks for the DPDK datapath is rejected at startup.

## Host preparation

```bash
# Hugepages (1 GB shown here; adjust to your NUMA layout)
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Bind the NICs to vfio-pci
sudo modprobe vfio-pci
sudo dpdk-devbind.py --status
sudo dpdk-devbind.py --bind=vfio-pci 0000:3b:00.0 0000:3b:00.1
```

Once bound, the interfaces disappear from `ip link`: the kernel no longer has a
stack on them, which is why the next hops are configured by hand (see below).

## Configuration

Enable the flavour and describe the hardware in `config.yaml`:

```yaml
upf:
  support_features:
    enable_bpf_datapath: no     # mutually exclusive with the DPDK datapath
    enable_dpdk_datapath: yes
  dpdk:
    lcores: "0-2"
    main_lcore: 0               # control plane; never polls
    n3:
      pci_address: "0000:3b:00.0"
      rx_queues: 1
      lcores: "1"
      next_hop_mac: "aa:bb:cc:dd:ee:01"   # gNB, or the router towards it
    n6:
      pci_address: "0000:3b:00.1"
      rx_queues: 1
      lcores: "2"
      next_hop_mac: "aa:bb:cc:dd:ee:02"   # data network gateway
```

Rules of thumb:

- Every lcore under a port needs its own RX queue, so `rx_queues` must be at
  least the number of lcores listed there.
- `main_lcore` runs PFCP, NRF and the rest of the control plane. The UPF keeps
  its control threads off the polling lcores automatically.
- `next_hop_mac` is required until ARP resolution runs in the fast path. The UPF
  *answers* ARP requests for its own addresses, but does not send any.

### One NIC or two

Giving `n3` and `n6` the **same** `pci_address` selects single-port mode: one
device carries both interfaces and the fast path separates the directions by
classifying each packet (GTP-U on UDP 2152 addressed to the N3 address is
uplink, everything else is downlink). The `n6` queue and lcore settings are then
ignored; only its `next_hop_mac` is used.

Two devices is the default and the faster option: each port gets its own queues
and its own lcores, so uplink and downlink never share a poll loop.

## How it fits together

```
upf_app ──► IUpfDatapath ──► DpdkDatapath            N4 session handling
                                 │
                                 ├─► DpdkSessionStore    SEID / F-TEID allocation
                                 ├─► SessionManager      rule state (shared)
                                 │       └─► DpdkSessionTables   TEID / UE-IP lookup
                                 └─► DpdkFastPath        EAL, ports, lcore workers
                                             └─► DpdkPipeline    per-packet work
```

The N4 thread builds a fresh rule set per session and publishes a pointer to it;
lcores read the tables lock-free and report a quiescent state each loop, which
is what lets the writer free the rule set it replaced (RCU, `rte_rcu_qsbr`).

`DpdkFastPath` is deliberately DPDK-free in its header: the DPDK headers reach
`netinet/ip.h` while the PFCP session model reaches `linux/ip.h`, and the two
define `struct iphdr` differently, so no translation unit may include both.

## What works

- Uplink: GTP-U decapsulation, PDR match, FAR apply action, forward to N6
- Downlink: UE IP lookup, GTP-U encapsulation with the PDU Session Container
  carrying the QFI (same wire format as the eBPF flavour)
- PDR selection by SDF filter: the most specific matching filter wins, ties are
  settled by precedence, and a PDR without a filter is the catch-all. The
  filter is parsed once per session with the same `SdfFilterParser` the eBPF
  flavour uses, and matched with the same scoring, so both agree on what a
  filter means
- QER gate status, and Maximum Bit Rate per direction policed with a token
  bucket (`rte_meter` srTCM). The rate is charged on the UE's own packet, before
  the tunnel headers are added or after they are stripped. This is policing,
  not the HTB-style shaping the eBPF flavour does — see below
- ARP replies for the UPF's own N3/N6 addresses
- GTP-U Echo Request replies
- Per-session traffic counters, per-lcore pipeline counters, port statistics

### QoS today: policing, not shaping

This is the one place where the DPDK flavour differs from eBPF in kind, not
just in degree, so it is worth being explicit.

The eBPF flavour does not queue packets itself. `qer_tc_kern.c` only
*classifies*: it looks up (SEID, QFI) and writes `skb->tc_classid`, and the
*kernel* shapes the traffic with the HTB hierarchy that `qer_tc_user.cpp`
builds on the N3 interface:

```
tc qdisc  dev n3  root handle 1:0 htb default <d> r2q <r2q>
└── class 1:<seid&0xffff>            rate = session AMBR        <- PDU session
    ├── class 1:<minor(seid,qfi)>    rate/ceil = GBR/MBR        <- QoS flow per QFI
    └── class 1:<default_minor>      rate/ceil = default class
tc filter dev n3 parent 1:0 bpf obj qer_tc_kern.c.o direct-action
```

With DPDK the kernel is out of the path, so there is no qdisc to delegate to
and no hierarchy yet. What exists instead is a **policer**: one `rte_meter`
srTCM token bucket per QER per direction, kept in the session's rule set. A
packet over the committed rate is dropped on the spot and counted as
`over rate`. Nothing is ever held back to smooth a burst, so a bursty flow sees
loss where HTB would have queued it, and GBR has no meaning at all — only the
MBR ceiling is enforced.

The buckets are shared by every lcore carrying the session, so each check takes
a spinlock for that QER and direction. With one polling lcore per port it is
never contended; if RSS spreads a session over several lcores, the lock is what
keeps the rate correct instead of letting each lcore grant the full MBR.

### Planned: the HTB hierarchy on `rte_sched`

The intended end state is the same hierarchy as the eBPF flavour, built with
DPDK's hierarchical scheduler (`rte_sched`, part of DPDK 21.11). The mapping:

| eBPF / TC | DPDK |
|---|---|
| root HTB qdisc on the N3 egress | `rte_sched_port` on the N3 TX port, rate = link rate |
| — | subport (one, later one per slice/DNN) |
| class `1:<seid>`, session AMBR | **pipe**, one per PDU session; token bucket = AMBR |
| class `1:<minor(seid,qfi)>`, MBR/GBR | **traffic class** in that pipe, one per QFI; TC rate = MBR |
| TC-BPF writing `skb->tc_classid` | `rte_sched_port_pkt_write(port, mbuf, subport, pipe, tc, queue, color)` |
| the kernel dequeueing and shaping | `rte_sched_port_enqueue()`, then `rte_sched_port_dequeue()` -> `rte_eth_tx_burst()` |
| `quantum` / `r2q` | WRR weights across the 4 best-effort queues |
| `generate_minor_id(seid, qfi)` | reused unchanged to pick the traffic class / queue |

Decisions taken for that work:

- **Downlink only**, mirroring eBPF: the scheduler sits on the N3 egress and
  uplink keeps the policer. The eBPF flavour skips UL QER for the same reason
  (see the comment in `xdp_far_apply_kern.c`: no TC HTB on the N6 egress).
- **The N6-polling lcore owns the scheduler.** A `rte_sched_port` instance has
  a single owner, so that lcore classifies, enqueues, dequeues and transmits on
  N3. No extra core and no rings, at the price of one constraint: shaping
  requires exactly one polling lcore on N6, which startup must validate and
  refuse otherwise. The alternative, kept in reserve for when N6 needs several
  lcores, is a dedicated traffic-manager lcore fed by an `rte_ring`.
- This replaces run-to-completion on the downlink: today a worker does
  RX -> process -> TX in one pass; with the scheduler it becomes
  RX -> classify -> enqueue, then dequeue -> TX in the same loop.

Constraints to design around:

- 13 traffic classes per pipe (12 strict-priority plus a best-effort class with
  4 WRR queues), so up to 12 QoS flows per session map one-to-one onto traffic
  classes, as the per-QFI HTB classes do today.
- Pipes come from a pool sized at init, so `max_pdu_sessions` sets the pipe
  count, and the session store gains a SEID -> pipe-id allocator.
- Each distinct rate needs a pipe profile. `rte_sched_subport_pipe_profile_add`
  works at runtime but the count is capped, so profiles are cached per rate —
  which fits an SMF handing out a handful of AMBR values.
- `rte_sched` caps each traffic class and prioritises between them; it does not
  *borrow* unused parent bandwidth the way HTB lends up to `ceil`. So
  `rate`/`ceil` becomes "AMBR at the pipe, MBR at the traffic class, priority
  instead of borrowing" — close in effect, not identical.

## Not implemented yet

| Missing | Effect |
|---|---|
| URR | The counters exist per session, but no usage report is sent |
| BAR buffering | A non-forwarding FAR drops instead of buffering |
| QoS shaping | Only policing: over-rate packets are dropped, never queued. GBR has no effect. See [Planned: the HTB hierarchy on `rte_sched`](#planned-the-htb-hierarchy-on-rte_sched) |
| ARP requests | Next hops come from the configuration |
| IPv6 | IPv4 only, in both the tunnel and the payload |
| Fragmentation | An encapsulated full-size packet needs an MTU of 1544 on N3; the ports ask for it and warn when the device cannot |

## What to expect on first run

The startup log shows the EAL arguments, each port (device, port id, MAC, queue
counts, link state), the next hops, the table capacity and one line per worker
lcore. On shutdown every worker prints its counters.

If no traffic flows, the per-lcore counters say which stage dropped it:
`no session` (no PFCP session for that TEID or UE IP), `no rule` (no PDR
matched, or its FAR is missing), `action` (FAR drop or a closed QER gate),
`over rate` (above the QER's MBR), `no next hop` (`next_hop_mac` not
configured), `malformed` (too short, not IPv4, or not addressed to us).
