# 🌐 OAI-UPF QoS WebUI

This directory contains the WebUI used to monitor OAI-UPF QoS behavior in a practical lab setup.

## ✨ What It Includes
- **Flask backend**: `backend/api_server.py`
- **Frontend page**: `frontend/index.html`
- **Frontend logic**: `frontend/app.js`
- **Styling**: `frontend/style.css`
- **Startup helper**: `start_webui.sh`
- **Optional session metadata**: `data/sessions.json`

## 🚀 Start the WebUI
```bash
cd gui/webui
sudo ./start_webui.sh
```

The service listens on port `5001` by default.

## 📊 Data Sources
The backend can combine multiple sources depending on the environment:
- `etc/config.yaml` for UPF configuration
- BPF maps when custom stats are available
- `tc -s class show` on the N3 interface when using the official upstream HTB mode
- interface byte counters from `/sys/class/net/*/statistics`
- optional PFCP session metadata from `data/sessions.json`

## 🧭 Intended Deployment
- **UPF host**: runs `upf` and this WebUI
- **PFCP helper host**: runs the PFCP session establishment script
- **TRex host**: runs the traffic profile

## 🧩 Optional Session Metadata
If `data/sessions.json` is present, the UI can enrich the session table with:
- user IDs
- UE IPs
- TEIDs
- QoS tiers
- GBR / MBR
- QFI
- precedence

If the file is missing, the backend can still show configuration and runtime information based on the UPF host state.

## 🔍 Notes
- Run with `sudo` so the backend can access `bpftool` and `tc` information.
- In official-source mode, the UI follows the upstream HTB/TC behavior instead of a custom datapath branch.
