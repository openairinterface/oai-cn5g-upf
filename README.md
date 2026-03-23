# 🚀 OAI-UPF (Official Source) with QoS WebUI

> **Updated:** March 23, 2026  
> **Mode:** Official OAI-UPF datapath (`src/` kept aligned with upstream)  
> **Focus:** Build the official UPF, monitor QoS behavior through the WebUI, and drive traffic with companion PFCP/TRex helper scripts.

## ✨ Overview
This repository keeps the **official OAI-UPF source tree** in `src/` while adding a practical monitoring workflow around it.

It is intended for a lab setup where:
- the **UPF** runs on the UPF host,
- the **WebUI** runs on the same UPF host,
- a **PFCP helper script** runs on the SMF-simulator host, and
- a **TRex helper script** runs on the traffic-generator host.

The monitoring layer is designed to work **with the upstream HTB/TC behavior** of the official UPF, rather than replacing the datapath with a custom in-kernel rate limiter.

## 🧭 Highlights
- ✅ **Official UPF source preserved**: `src/` follows the upstream OAI implementation.
- 🌐 **Full-stack WebUI**: Flask backend plus HTML/CSS/JS frontend under `gui/webui/`.
- 📊 **QoS-aware monitoring**: Interface rates, PFCP session overview, and runtime QoS visualization.
- 🎯 **Official HTB/TC mode**: The UI is aligned with the upstream N3 HTB class behavior.
- 🧪 **Companion helper scripts**: PFCP session setup and TRex traffic generation used alongside this repository.

## 🔄 Datapath Model
In the official source flow, downlink QoS follows the upstream OAI path:

```text
DN -> N6 -> XDP session lookup -> TC ingress redirect -> N3 HTB classes
```

This means:
- XDP performs early packet/session processing.
- TC and HTB enforce the official upstream class-based shaping behavior.
- The WebUI observes the system from the outside using configuration files, interface counters, BPF state, and HTB class statistics.

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
│   └── webui/        # QoS monitoring frontend + backend
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

## 🧩 PFCP and TRex Helper Scripts
In our lab workflow, the PFCP and TRex helpers are placed under:

- `oai-cn5g-fed/test/block_test/SMF_scripts/oripfcp_qos_10_with_prio.py`  
  Used on the **SMF simulator / PFCP client host** to establish 10 PFCP sessions.
- `oai-cn5g-fed/test/block_test/Trex_scripts/oriudp_10_pkt_src_ip_split.py`  
  Used on the **TRex host** to generate per-user UDP traffic according to the QoS layout.

## ▶️ Typical Lab Workflow
### 1. Start the official UPF
```bash
sudo upf -c etc/config.yaml -o
```

### 2. Start the WebUI on the UPF host
```bash
cd gui/webui
sudo ./start_webui.sh
```

### 3. Establish PFCP sessions from the PFCP helper host
```bash
python3 oai-cn5g-fed/test/block_test/SMF_scripts/oripfcp_qos_10_with_prio.py
```

### 4. Start TRex on the traffic-generator host (run as `root`)
```bash
./t-rex-64 -i --no-scapy-server -c 30
```

### 5. Open the TRex console (run as `root`)
```bash
./trex-console
```

### 6. Launch the companion traffic profile from the TRex console
```bash
start -f oai-cn5g-fed/test/block_test/Trex_scripts/oriudp_10_pkt_src_ip_split.py -p 1 -m 100% -d 600
```

## 📊 What the WebUI Shows
The WebUI provides several layers of visibility:

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
- custom BPF counters when present, or
- official upstream HTB class counters on the N3 side.

In official-source mode, the UI is intended to reflect the **actual upstream HTB-based QoS behavior** rather than a custom token-bucket branch.

## 📐 Stable Official QoS Profile Used in Our Lab
For the official source branch, a stable 10-user profile commonly used in testing is:

- **HIGH** (2 users): `GBR 0.8 Gbps`, `MBR 1.2 Gbps`
- **MEDIUM** (3 users): `GBR 0.4 Gbps`, `MBR 0.8 Gbps`
- **LOW** (5 users): `GBR 0.2 Gbps`, `MBR 0.4 Gbps`

Aggregate totals:
- **Total GBR**: `3.8 Gbps`
- **Total MBR**: `6.8 Gbps`

This keeps the official upstream implementation in a range that is easier to validate consistently in lab tests.

## 🔍 Troubleshooting
### WebUI shows no active sessions
Check:
- the UPF process is running,
- PFCP sessions have been established,
- `bpftool` is available on the UPF host,
- `tc` HTB classes exist on the N3 interface when using official mode.

### WebUI shows configuration but no live movement
Check:
- traffic is actually traversing the UPF,
- TRex is sending to the right UE IP range,
- the PFCP helper created sessions successfully,
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
- Companion PFCP/TRex scripts are part of the test workflow and are expected under `oai-cn5g-fed/test/block_test/`