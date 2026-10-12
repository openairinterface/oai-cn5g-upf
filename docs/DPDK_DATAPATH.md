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
- QER gate status, and Maximum Bit Rate per direction with a token bucket
  (`rte_meter` srTCM). The rate is charged on the UE's own packet, before the
  tunnel headers are added or after they are stripped
- ARP replies for the UPF's own N3/N6 addresses
- GTP-U Echo Request replies
- Per-session traffic counters, per-lcore pipeline counters, port statistics

### Notes on the QoS enforcement

The token buckets live in the session's rule set and are shared by every lcore
that carries the session, so each check takes a spinlock for that QER and
direction. With the usual one-lcore-per-port setup it is never contended. If a
session is spread over several lcores by RSS the lock keeps the rate correct at
the cost of that contention.

GBR is not enforced: only the MBR ceiling is. A QER with no MBR for a direction
leaves that direction unmetered.

## Not implemented yet

| Missing | Effect |
|---|---|
| URR | The counters exist per session, but no usage report is sent |
| BAR buffering | A non-forwarding FAR drops instead of buffering |
| QER GBR | Only the MBR ceiling is enforced |
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
