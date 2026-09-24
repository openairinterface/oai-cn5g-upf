<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Downlink Buffering and Paging

## 1. What it is

This is the UPF half of the network-triggered Service Request (3GPP TS 23.502
§4.2.3.3). When a UE goes CM-IDLE, the SMF changes the session's downlink FAR
to BUFF (with NOCP). The first downlink packet that hits that FAR makes the UPF
send a PFCP Session Report Request with a Downlink Data Report (DLDR, TS 29.244
§7.5.8.2) to the SMF. The SMF asks the AMF to page the UE. Once the UE is back,
the SMF installs new downlink rules towards the gNB's new TEID, and the UPF
sends the packets it held on N3.

```
DN --> UPF: DL packet hits BUFF FAR --> held, one DLDR --> SMF --> AMF pages UE
UE service request --> SMF: SMReq ends buffering --> UPF replays held packets on N3
```

It works on both datapaths. It is off by default: with
`enable_dl_buffering: no`, the SMF is still notified, but the buffered packets
are dropped, as before.

## 2. Which switches matter

The buffering keys are in `upf.datapath_configuration`. `enable_bar` and
`enable_bpf_datapath` are in `upf.support_features`.

| **Datapath** | **`enable_bar`** | **`enable_dl_buffering`** | **DLDR to the SMF** | **Buffered packets** |
| --- | --- | --- | --- | --- |
| simple switch | ignored | `no` | yes | dropped |
| simple switch | ignored | `yes` | yes | held and replayed |
| eBPF / XDP | `no` | ignored | no | dropped |
| eBPF / XDP | `yes` | `no` | yes, from the XDP BAR program | dropped |
| eBPF / XDP | `yes` | `yes` | yes, from the XDP BAR program | captured over AF_XDP, held and replayed |

On the eBPF datapath `enable_bar` is the master switch. With `enable_bar: no`,
nothing in this document applies there. The simple switch does not use a BAR.

## 3. Configuration

| **Setting** | **Meaning** | **Default** | **Range** |
| --- | --- | --- | --- |
| `enable_dl_buffering` | hold BUFF packets and replay them, instead of dropping them | `no` | yes / no |
| `dl_buffer_max_pkts_per_session` | packets held per session | 64 | 1-1024 |
| `dl_buffer_max_kib_per_session` | KiB held per session | 128 | 4-4096 |
| `dl_buffer_max_pkts_total` | packets held across all sessions | 16384 | 64-262144 |
| `dl_buffer_max_kib_total` | KiB held across all sessions (32 MiB) | 32768 | 256-524288 |
| `default_buffering_duration_ms` | how long packets are held (T_guard) | 20000 | 1000-120000 |
| `xsk_frame_size` | eBPF only: bytes per AF_XDP frame | 4096 | 2048 or 4096 |
| `xsk_frames_per_queue` | eBPF only: frames and ring slots per N6 RX queue | 2048 | 512-16384, power of two |
| `xsk_umem_max_mib_total` | eBPF only: cap on all UMEMs together | 256 | 8-1024 |

Every bound is finite. A value of `0`, a value out of range, a per-session
bound above its total, an `xsk_frame_size` other than 2048 or 4096, or an
`xsk_frames_per_queue` that is not a power of two all fail validation, and the
UPF refuses to start.

Bytes are charged by allocated size, not payload: each packet costs its length
plus 64 B of GTP-U headroom plus bookkeeping. A packet over any bound is
dropped (drop-tail); the ones already held are kept.

The UPF's own bounds and T_guard always apply. On the eBPF datapath, a BAR
sent by the SMF (Suggested Buffering Packets Count, DL Data Notification Delay)
is also applied by the XDP BAR program. The SMF does not need to send a BAR.

## 4. How it behaves

**One DLDR per episode.** The first packet that hits the buffering rule sends
the DLDR. Later packets are held without another report. The UPF sends the
DLDR again only in these cases:

* The report could not be queued, for example because the association has no
  usable SMF address. It is retried with the next packet, at most once per
  second.
* The SMF did not answer the report within the PFCP retransmission budget. The
  UPF logs `peer not responding, re-arming`, and the next packet sends a new
  DLDR.
* T_guard expired (below).

**What each Session Modification Request does to the held packets.** The UPF
decides once, at the end of each accepted request. A rejected request changes
nothing.

| **Verdict** | **When** | **Effect** |
| --- | --- | --- |
| FLUSH | the buffering FAR is removed, or updated from BUFF to FORW | replay |
| DISCARD | the buffering PDR is removed without that, or no buffering FAR is left | held packets are freed |
| KEEP | anything else, for example the UL rules of the Service Request | packets stay held |

**Replay.** After the response to the SMF has been sent, the held packets go
through the normal downlink lookup again, in order, against the new rules. So
they leave towards the new TEID, with the new QFI. A packet that matches a
buffering rule again is held again; one that matches nothing is dropped. With
`enable_urr: yes`, a held packet is counted once, when it is replayed.

**T_guard.** Packets held longer than `default_buffering_duration_ms` are
discarded, and the next packet can send a new DLDR. The default, 20 s, is
longer than the AMF's paging budget. The check runs every second.

**Session end.** A Session Deletion, an association release or a heartbeat
give-up discards what the session holds. Packets still in flight for it are
dropped.

**Logs.** All at `info` unless noted:

| **Line** | **Meaning** |
| --- | --- |
| `Sending SESSION REPORT REQUEST (DLDR) seid … pdr …` | a DLDR was sent, from either datapath |
| `DL buffer seid …: verdict KEEP\|FLUSH\|DISCARD, detached N, valid M` | the verdict for one request; only when buffering is involved |
| `DL buffer seid …: replay sent N, dropped N, rebuffered N` | the result of a FLUSH |
| `DL buffer seid …: T_guard expired, N discarded, …` | an expiry |
| `DL buffer seid …: tombstoned, N discarded` | a session ended while buffering |
| `DL buffer stats: stored …, held …, …` | the global counters, whenever they change |
| `DLDR trxn … seid …: peer not responding, re-arming` (`warn`) | the SMF did not answer a DLDR |

The counters always satisfy `stored = flushed + discarded + expired + held`.

## 5. eBPF / XDP datapath

The XDP BAR program sends the DDN event to user space, which turns it into the
DLDR. With `enable_dl_buffering: yes`, it also redirects each buffered packet
to an AF_XDP socket instead of dropping it. User space copies it into the same
store the simple switch uses, and the rest of §4 applies unchanged.

* **One socket and UMEM per N6 RX queue**, at most 64 queues. The UMEMs take
  queues × `xsk_frames_per_queue` × `xsk_frame_size` bytes, 8 MiB per queue
  with the defaults, and that must fit `xsk_umem_max_mib_total`. With the
  defaults that is 32 queues; a host with more must lower
  `xsk_frames_per_queue` or raise the cap.
* **Copy mode, always.** The sockets are bound with `XDP_COPY` in native and
  SKB mode alike. Capture is a slow path; zero-copy would put the whole N6
  queue, forwarded traffic included, on the UMEM. libxdp never loads or
  replaces an XDP program: the UPF's own program stays attached.
* **Locked memory.** UMEM registration pins its pages against
  `RLIMIT_MEMLOCK` unless the process has `CAP_IPC_LOCK`. A privileged
  container has it. Otherwise add `CAP_IPC_LOCK` or raise the limit
  (`--ulimit memlock=-1`). Without either, the socket creation fails with
  `Cannot allocate memory`.
* **Replay sender.** XDP owns N3, so the replay goes out through a
  transmit-only GTP-U socket, bound to the N3 IPv4 address with an ephemeral
  source port, towards port 2152. It uses the kernel stack, so the host needs a
  route and a neighbour entry to the gNB. No user-space socket listens on 2152.
* **Failure does not stop the UPF.** If the sockets cannot be set up, the UPF
  logs one `error` (`DL buffer AF_XDP capture disabled, buffered packets are
  dropped: …`) and runs on with capture off: the DLDR is still sent and the
  buffered packets are dropped. The same happens if polling fails later.
  Capture then stays off until the UPF restarts.

At start, a successful setup logs `DL buffer AF_XDP capture on <n6>: N RX
queue(s), …`. `ss --xdp` lists the sockets.

## 6. Requirements

**SMF.** The SMF must install no downlink PDR at session establishment and
must enable paging: `paging.enable: yes`, and
`upfs[].config.enable_dl_pdr_in_pfcp_session_establishment: no` for this UPF.
This has been developed against the SMF branch `smf_paging_new`, which refuses
to start with both set.

**Build.** The UPF now links libxdp (xdp-tools v1.5.8). `make setup` clones it
and builds it against the in-tree libbpf v1.5.0 into `build/ext/xdp-tools`. It
is not installed system-wide, and the images copy `libxdp.so.1` next to
`libbpf.so.1`. It adds the `m4` and `pkg-config` packages (`libpcap-devel`,
`m4` and `pkgconfig` on Fedora/RHEL). **Re-run `make setup` on an existing
build tree** before `make build`; the link fails without libxdp. This applies
to the simple switch as well, because it is the same binary.

## 7. Limitations

* **eBPF needs `enable_bar`.** Without it, the eBPF datapath neither reports
  nor holds (§2). Capture also needs `enable_dl_buffering`.
* **IPv4 only.** IPv6 is not covered; the SMF arms IPv4 only. Ethernet PDU
  sessions are not supported. On the eBPF datapath only untagged Ethernet +
  IPv4 frames are captured: 802.1Q-tagged frames never reach the BAR program.
* **Ordering.** Replayed packets can be reordered against new downlink packets
  forwarded during the replay.
* **ToS.** Replayed packets lose their ToS marking.
* **Short refusal windows.** Packets are refused, not held, between a Remove
  and a Create inside one request, and while new rules are being published.
  The DLDR still goes out.
* **PFCP serialisation.** All PFCP transactions now go through one lock. It is
  covered by manual runs only.
* **Update PDR on the buffering PDR.** An Update PDR on the buffering PDR
  itself makes the held packets unmatchable, so they are dropped at the next
  KEEP. An Update PDR that re-points it from the BUFF FAR to a FORW FAR is not
  seen as the end of buffering: nothing is replayed, and the DDN latch is only
  released by T_guard or session deletion (on eBPF, also by the next
  buffering request). The OAI SMF sends neither.
* **Usage reporting.** A held packet that is later dropped (overflow, DISCARD,
  T_guard, session end) is never counted in a Usage Report.
* **Duplicate DLDR.** At most one duplicate DLDR per episode can appear: when a
  request starts buffering again after an episode that never flushed, when a
  late SMF answer arrives after the UPF gave up on it, or, on eBPF, for a
  packet in flight while M4 is applied. The SMF tolerates it.
* **No zero-copy AF_XDP**, and no automatic restart of capture after a fatal
  poll error.
