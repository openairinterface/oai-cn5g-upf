# 🚀 OAI-UPF WebUI for Datapath QoS Observability

> **Updated:** April 16, 2026  
> **Mode:** Official OAI-UPF datapath (`src/` kept aligned with upstream)  
> **Focus:** Provide a WebUI to observe UPF datapath behavior and runtime QoS-related KPIs from a single interface.

## ✨ Overview
This repository keeps the **official OAI-UPF source tree** in `src/` while adding a practical **WebUI-based observability layer** around it.

The goal of the WebUI is to provide a single place to inspect datapath behavior and QoS-related runtime information, instead of relying on multiple separate tools to collect and compare results manually.

The WebUI is intended to support visibility into:
- throughput,
- session-level QoS information,
- datapath activity,
- class-based shaping behavior, and
- additional KPIs such as latency or packet loss metrics when they are exposed by the measurement backend.

The monitoring layer is designed to work **with the upstream HTB/TC behavior** of the official UPF, rather than replacing the datapath with a custom in-kernel rate limiter.

## 🧭 Design Intent
This contribution is intended as a **generic Web interface for UPF datapath observability**.

It is **not designed to be TRex-dependent**.  
Traffic may come from TRex in a lab setup, but TRex is only one possible traffic generator among others. The WebUI is meant to visualize datapath behavior and collected KPIs independently from the specific traffic generation tool.

## 🧭 Highlights
- ✅ **Official UPF source preserved**: `src/` follows the upstream OAI implementation.
- 🌐 **Full-stack WebUI**: Flask backend plus HTML/CSS/JS frontend under `gui/webui/`.
- 📊 **QoS-aware monitoring**: Interface rates, PFCP session overview, and runtime QoS visualization.
- 🎯 **Official HTB/TC mode**: The UI is aligned with the upstream N3 HTB class behavior.
- 🔎 **Single-pane observability goal**: Centralize datapath-related runtime information in one interface.

## 🔄 Datapath Model
In the official source flow, downlink QoS follows the upstream OAI path:

```text
DN -> N6 -> XDP session lookup -> TC ingress redirect -> N3 HTB classes
```

This means:
- XDP performs early packet/session processing.
- TC and HTB enforce the official upstream class-based shaping behavior.
- The WebUI observes the system from the outside using configuration files, interface counters, PFCP session metadata, BPF-visible state when available, and HTB class statistics.

## 📜 License
The source code is distributed under `Collaborative Standards Software License v1.0 (CSSL v1.0)`.
For more details, visit the [OAI Website](https://openairinterface.org/oai-cssl/).

The full text of `Collaborative Standards Software License v1.0` is also included in the [LICENSE](LICENSE) file at the root of this repository.

Certain files in the repository are using MIT License and documentation is distributed under
Creative Commons Attribution 4.0 International license.

For third-party softwares, please refer to [NOTICE](NOTICE) file.

## 📂 Repository Layout
```text
.
├── build/            # Build system and generated output
├── ci-scripts/       # CI helpers
├── docker/           # Container build files
├── docs/             # Documentation
├── etc/              # Runtime configuration (config.yaml)
├── gui/
│   └── webui/        # Datapath observability frontend + backend
├── scripts/          # Container/runtime helper scripts
└── src/              # Official OAI-UPF source tree
```

## 🛠️ Build the Official UPF
Install dependencies and build the UPF as usual:

```bash
make setup
make install
```

Run the UPF:

```bash
sudo upf -c etc/config.yaml -o
```

## 🌐 Start the WebUI
The WebUI lives under `gui/webui/`.

```bash
cd gui/webui
sudo ./start_webui.sh
```

Then open:
- [http://localhost:5001](http://localhost:5001)
- `http://<UPF-host-ip>:5001`

## 📊 What the WebUI Shows
The WebUI is intended to centralize runtime datapath visibility.

### UPF Configuration
Read from `etc/config.yaml`, including:
- BPF datapath switch
- QoS switch
- N3 / N4 / N6 interfaces
- N6 gateway and runtime basics

### PFCP Session Overview
Session metadata can be shown from `gui/webui/data/sessions.json` when available.

Typical fields include:
- user / UE IP
- TEID
- QoS tier
- GBR / MBR
- QFI
- precedence

### Runtime Traffic View
Depending on the environment, the backend can use:
- interface counters,
- PFCP-derived session information,
- custom BPF counters when present, or
- official upstream HTB class counters on the N3 side.

In official-source mode, the UI is intended to reflect the **actual upstream HTB-based QoS behavior** rather than a custom token-bucket branch.

### KPI Direction
The WebUI is intended to gather datapath KPIs in one place.  
Today this mainly focuses on throughput and QoS-related runtime observability. The design also allows extension toward latency, packet loss ratio (PLR), and other KPIs when these measurements are made available by the surrounding test or measurement environment.

## 🧩 Optional Lab Traffic Workflow
A lab setup may use companion tools to generate traffic and create PFCP sessions, but these tools are **not a functional requirement of the WebUI design**.

For example, in one lab workflow:
- a PFCP helper script may run on an SMF-simulator host,
- a traffic generator such as TRex may run on a separate host,
- the WebUI runs on the UPF host and visualizes the resulting datapath behavior.

Example helper locations used in one setup:
- `oai-cn5g-fed/test/block_test/SMF_scripts/oripfcp_qos_10_with_prio.py`
- `oai-cn5g-fed/test/block_test/Trex_scripts/oriudp_10_pkt_src_ip_split.py`

These are **example companion tools for lab validation**, not mandatory dependencies of the WebUI itself.

## ▶️ Example Lab Workflow
### 1. Start the official UPF
```bash
sudo upf -c etc/config.yaml -o
```

### 2. Start the WebUI on the UPF host
```bash
cd gui/webui
sudo ./start_webui.sh
```

### 3. Optionally establish PFCP sessions from a PFCP helper host
```bash
python3 oai-cn5g-fed/test/block_test/SMF_scripts/oripfcp_qos_10_with_prio.py
```

### 4. Optionally start TRex on a traffic-generator host
```bash
./t-rex-64 -i --no-scapy-server -c 30
```

### 5. Optionally open the TRex console
```bash
./trex-console
```

### 6. Optionally launch a traffic profile from the TRex console
```bash
start -f oai-cn5g-fed/test/block_test/Trex_scripts/oriudp_10_pkt_src_ip_split.py -p 1 -m 100% -d 600
```

## 📐 Example QoS Profile Used in One Lab Setup
For one 10-user validation scenario, the following profile has been used:

- **HIGH** (2 users): `GBR 0.8 Gbps`, `MBR 1.2 Gbps`
- **MEDIUM** (3 users): `GBR 0.4 Gbps`, `MBR 0.8 Gbps`
- **LOW** (5 users): `GBR 0.2 Gbps`, `MBR 0.4 Gbps`

Aggregate totals:
- **Total GBR**: `3.8 Gbps`
- **Total MBR**: `6.8 Gbps`

This is only an **example lab profile**, not a requirement of the WebUI architecture.

## 🔍 Troubleshooting
### WebUI shows no active sessions
Check:
- the UPF process is running,
- PFCP sessions have been established when session visualization is expected,
- `bpftool` is available on the UPF host when BPF-related information is used,
- `tc` HTB classes exist on the N3 interface when using official mode.

### WebUI shows configuration but no live movement
Check:
- traffic is actually traversing the UPF,
- the traffic source is targeting the expected UE/session space,
- PFCP session setup has been completed when session-aware monitoring is expected,
- the N3 / N6 interface names in `etc/config.yaml` match the real host.

### WebUI port is already in use
`gui/webui/start_webui.sh` automatically cleans up the previous process on port `5001` before starting a new backend.

## 📚 Related Files
- `etc/config.yaml`
- `gui/webui/backend/api_server.py`
- `gui/webui/frontend/index.html`
- `gui/webui/frontend/app.js`
- `gui/webui/frontend/style.css`
- `gui/webui/start_webui.sh`

## 📝 Notes
- This repository keeps the **official OAI-UPF source** in place.
- The WebUI is meant to **observe** the official datapath, not redefine it.
- Traffic generation tools such as TRex may be used in lab validation, but the WebUI is **not conceptually tied to a specific traffic generator**.