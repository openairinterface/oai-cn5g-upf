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
UE service request --> SMF: a PFCP Session Modification Request ends buffering --> UPF replays held packets on N3
```

It works on both datapaths. It is off by default: with
`enable_dl_buffering: no`, the SMF is still notified (on eBPF only with
`enable_bar: yes`), and the buffered packets are dropped.

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
| `dl_buffer_max_hold_ms` | maximum hold time: how long a packet is held at most | 20000 | 1000-120000 |
| `xsk_frame_size` | eBPF only: bytes per AF_XDP frame | 4096 | 2048 or 4096 |
| `xsk_frames_per_queue` | eBPF only: frames and ring slots per N6 RX queue | 2048 | 512-16384, power of two |
| `xsk_umem_max_mib_total` | eBPF only: cap on all UMEMs together | 256 | 8-1024 |

Every bound is finite. A value of `0`, a value out of range, a per-session
bound above its total, an `xsk_frame_size` other than 2048 or 4096, or an
`xsk_frames_per_queue` that is not a power of two all fail validation, and the
UPF refuses to start.

The maximum hold time is a UPF-local bound; it is not the DL Buffering Duration
IE (TS 29.244 §8.2.29), which this UPF does not apply.

Bytes are charged by allocated size, not payload: each packet costs its length
plus 64 B of GTP-U headroom plus bookkeeping. A packet over any bound is
dropped (drop-tail); the ones already held are kept.

The UPF's own bounds and the maximum hold time always apply. On the eBPF
datapath, the XDP BAR program also applies a BAR sent by the SMF, that is its
Suggested Buffering Packets Count and its Downlink Data Notification Delay
(TS 29.244 §8.2.28), with the differences listed in §7. The SMF does not need
to send a BAR.

## 4. How it behaves

**Terms.** Terms marked UPF-internal are not 3GPP terms.

| **Term** | **Meaning** |
| --- | --- |
| Downlink Data Report (DLDR) | A PFCP Session Report Request (TS 29.244 §7.5.8) with Report Type DLDR (§8.2.21) and a Downlink Data Report IE (Table 7.5.8.2-1) that carries the PDR ID. TS 23.502 §4.2.3.3 step 2a calls it "Data Notification". |
| DDN event | UPF-internal. The record the XDP BAR program writes to its ring buffer. DDN event (XDP ring) → PFCP Session Report Request, Report Type DLDR + Downlink Data Report IE → "Data Notification" in TS 23.502 §4.2.3.3 step 2a. |
| Buffering FAR, buffering PDR | A FAR whose Apply Action has BUFF, and a PDR that uses such a FAR. The OAI SMF calls them the paging FAR and the paging PDR. |
| Notification latch | UPF-internal. Set when a DLDR is sent, so that later packets do not report again: Apply Action NOCP asks to notify the CP function of the first buffered downlink packet. On the simple switch it also stays set while a report that could not be queued waits for its retry. One per PDR on the simple switch (`pfcp_pdr::notified_cp`), one per session on the eBPF datapath (`bar_state.last_ddn_ns`). |
| Re-arm | UPF-internal. Clear the notification latch, so that the next buffered downlink packet reports again. The events that re-arm it are listed below. |
| Buffering period | UPF-internal. A buffering period runs from the moment a FAR of the session gets Apply Action BUFF until that FAR leaves BUFF or is removed, or the session is deleted. Expiry of the maximum hold time does not end it. |
| Maximum hold time | UPF-internal. How long a packet is held at most (`dl_buffer_max_hold_ms`, §3). |
| Verdict | UPF-internal. FLUSH, DISCARD or KEEP: what the end of a Session Modification decides for the held packets (table below). |
| Tombstone | UPF-internal. The DL buffer record of a deleted session, kept for one tick so that late packets count as `tombstone_dropped` (session deleted), not `no_record_dropped`. |
| `rule_uid` | UPF-internal. Identifies one instance of a PDR. An Update PDR replaces the PDR by a copy with a new `rule_uid`, and the DL buffer holds packets per `rule_uid`. |

**Normally one Downlink Data Report per buffering period.** The first packet
that hits the buffering rule sends the report; later packets are held without
another one. The UPF reports again only in these cases (and, on the eBPF
datapath, when a BAR sets a non-zero Downlink Data Notification Delay; see
§7):

* The report could not be queued, for example because the association has no
  usable SMF address. On the simple switch it is retried with the next packet,
  at most once per second. On the eBPF datapath the next packet retries at
  once, so every packet can cause a retry and a log line until the address is
  known.
* The SMF did not answer the report. The UPF retransmits it up to 3 times, one
  second apart, and gives up within about 5 s. It then logs
  `peer not responding, re-arming`, and the next packet sends a new DLDR.
* The maximum hold time expired (below).

**When the notification is re-armed.** After the first report of a buffering
period, the UPF reports again only once the notification latch is re-armed,
or, on the eBPF datapath, once a BAR's Downlink Data Notification Delay
allows a repeat:

| **Event** | **Simple switch** (per PDR) | **eBPF / XDP** (per session, `bar_state.last_ddn_ns`) |
| --- | --- | --- |
| A Session Modification starts buffering in a session that had no buffering FAR | not cleared here (a newly created PDR starts with a clear latch; see Limitations for the Update PDR case) | cleared before the new rules are applied |
| An Update FAR takes a FAR out of BUFF | cleared for the PDRs that use that FAR | cleared after the new rules are applied |
| A buffering PDR or FAR is removed | a removed PDR takes its latch with it; removing only the FAR clears nothing | cleared after the new rules are applied |
| The SMF does not answer a Downlink Data Report | cleared | cleared |
| A Downlink Data Report could not be queued | cleared at the next once-per-second check | cleared at once |
| The maximum hold time expires while packets are held | cleared | cleared |
| A BAR sets a non-zero Downlink Data Notification Delay | not applied | a new report is allowed once that delay has passed since the last one |
| The DDN ring buffer is full when the report is due | — | the latch is restored, so the next DL packet tries again |
| The session is deleted | the rules are deleted | the state is erased |

On the eBPF datapath, a replayed packet goes through the same downlink lookup
as on the simple switch. If it matches a buffering PDR with NOCP again, it is
reported through that PDR's own latch (the simple-switch column), not through
`bar_state`. If that report could not be queued, the next once-per-second check
re-arms that latch and clears `bar_state`.

**What each Session Modification Request does to the held packets.** The UPF
decides once, at the end of each accepted request. A rejected request changes
nothing.

| **Verdict** | **When** | **Effect** |
| --- | --- | --- |
| FLUSH | the buffering FAR is removed, or updated from BUFF to FORW | replay |
| DISCARD | the buffering PDR is removed without that, or no buffering PDR is left | held packets are freed |
| KEEP | anything else, for example the UL rules of the Service Request | packets stay held |

**Replay.** After the response to the SMF has been sent, the held packets go
through the normal downlink lookup again, in order, against the new rules. So
they leave towards the new TEID, with the new QFI. A packet that matches a
buffering rule again is held again; one that matches nothing is dropped. With
`enable_urr: yes`, a held packet is counted once, when it is replayed.

**Maximum hold time.** When the oldest packet held for a session has waited
`dl_buffer_max_hold_ms`, all the packets held for that session are discarded,
and the next packet can send a new DLDR. The default, 20 s, is
longer than the AMF's paging budget. The check runs every second. The maximum
hold time re-arms the notification only for a session that holds packets.
With `enable_dl_buffering: no`, or when eBPF capture is off, a report that the
SMF answered is not repeated until the SMF changes the rules, unless, on the
eBPF datapath, a BAR sets a non-zero Downlink Data Notification Delay (see
§7).

**Session end.** A Session Deletion, an association release or a heartbeat
give-up discards what the session holds. Packets still in flight for it are
dropped.

**Logs.** All at `info` unless noted:

| **Line** | **Meaning** |
| --- | --- |
| `Sending SESSION REPORT REQUEST (DLDR) seid … pdr …` | a DLDR was sent, from either datapath |
| `DL buffer seid …: verdict KEEP\|FLUSH\|DISCARD, detached N, buffering PDRs M` | the verdict for one request; only when buffering is involved |
| `DL buffer seid …: replay sent N, dropped N, rebuffered N` | the result of a FLUSH |
| `DL buffer seid …: maximum hold time expired, N discarded, …` | an expiry |
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
The OAI SMF with paging support refuses to start with both set.

**Build.** The UPF links libxdp (xdp-tools v1.5.8). `make setup` clones it
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
  IPv4 frames are captured: 802.1Q-tagged frames never reach the XDP BAR
  program.
* **Ordering.** Replayed packets can be reordered against new downlink packets
  forwarded during the replay.
* **ToS.** Replayed packets lose their ToS marking.
* **Short refusal windows.** Packets are refused, not held, between a Remove
  and a Create inside one request, and while new rules are being published.
  The DLDR still goes out.
* **Update PDR on the buffering PDR.** An Update PDR on the buffering PDR
  itself makes the held packets unmatchable, so they are dropped at the next
  KEEP. An Update PDR that re-points it from the BUFF FAR to a FORW FAR is not
  seen as the end of buffering: nothing is replayed, and the PDR keeps its
  notification latch. It is re-armed only by the events in the §4 table that
  still apply, for example when the SMF never answered the report, or when the
  maximum hold time expires in a later buffering period that holds packets. On
  eBPF, a request that starts buffering re-arms it only if the session has no
  buffering FAR left. The OAI SMF sends neither.
* **Usage reporting.** A held packet that is later dropped (overflow, DISCARD,
  maximum hold time, session end) is never counted in a Usage Report.
* **Duplicate reports.** A duplicate Downlink Data Report can appear when a
  request starts buffering again after a buffering period that never flushed,
  when a late SMF answer arrives after the UPF gave up on it, or, on the eBPF
  datapath, for a packet in flight while the Session Modification that ends
  buffering is being applied. The OAI SMF ignores a report while it is already
  paging the UE.
* **No zero-copy AF_XDP**, and no automatic restart of capture after a fatal
  poll error.
* **Retry pacing after a report that could not be queued.** The simple switch
  retries at most once per second. The eBPF datapath retries with the next DL
  packet, without pacing: while the SMF address is unknown or the N4 task
  refuses the request, every DL packet that hits the buffering rule can cause a
  new report attempt and a log line.
* **The Session Report Response is not acted on.** The UPF only logs it. Its
  Cause, the DROBU flag and an Update BAR are ignored, so a paging failure that
  the SMF signals there does not discard the held packets: they stay until a
  Session Modification ends buffering, the session is deleted, or the maximum
  hold time expires.
* **No Downlink Data Service Information.** The Downlink Data Report carries
  only the PDR ID. TS 29.244 asks for the QFI (Downlink Data Service
  Information) over N4 when it is known.
* **BAR parameters.** The UPF does not advertise the DDND, DLBD or UDBC
  features. The eBPF datapath still applies a BAR's Downlink Data Notification
  Delay, as the minimum gap between repeated reports rather than as a delay
  before the first one, and its Suggested Buffering Packets Count, to downlink
  packets only. The simple switch applies neither.
* **One notification per session on eBPF.** The eBPF datapath keeps one
  notification latch per session, the simple switch one per PDR. TS 29.244
  asks for a report per QoS flow and FAR in 5GC. With the OAI SMF, which
  installs one paging PDR per session, this makes no difference.
* **No repeated report without held packets.** The maximum hold time re-arms
  the notification only for a session that holds packets. With
  `enable_dl_buffering: no`, or when eBPF capture is off, a report that the SMF
  answered is not repeated until the SMF changes the rules. The exception is
  the eBPF datapath with a BAR that sets a non-zero Downlink Data Notification
  Delay: a DL packet that arrives at least that delay after the last report
  triggers a new one.
* **NOCP without BUFF.** TS 29.244 allows NOCP only together with BUFF, and the
  OAI SMF always sets both. If a FAR carries NOCP without BUFF, the datapaths
  differ. The simple switch sends a Downlink Data Report for the first such
  packet (and again whenever its notification latch is re-armed), and it
  forwards every such packet when the FAR has FORW and drops it otherwise. The
  eBPF datapath sends no report: it forwards with FORW, drops with DROP, and
  passes the packet to the host network stack when NOCP is the only flag.
