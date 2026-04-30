#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
"""
OAI-UPF Web Monitoring Backend API Service
Provides UPF configuration, user session information, and real-time BPF statistics
"""
import os
import sys
import json
import time
import yaml
import struct
import re
import subprocess
import socket
from datetime import datetime
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

# Configuration paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))


def load_env_file(env_file):
    """Load simple KEY=VALUE entries from a local .env file if present."""
    if not env_file or not os.path.exists(env_file):
        return

    with open(env_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value


load_env_file(os.environ.get("WEBUI_ENV_FILE", os.path.join(BASE_DIR, ".env")))

CONFIG_FILE = os.environ.get(
    "WEBUI_CONFIG_FILE",
    os.path.join(REPO_ROOT, "etc", "config.yaml"),
)
SESSIONS_FILE = os.environ.get(
    "WEBUI_SESSIONS_FILE",
    os.path.join(BASE_DIR, "data", "sessions.json"),
)

# BPF monitoring configuration
NUM_USERS = int(os.environ.get("WEBUI_NUM_USERS", "10"))
TEID_BASE = int(os.environ.get("WEBUI_TEID_BASE", "0x10"), 0)
DISPLAY_TARGET_MULTIPLIER = float(
    os.environ.get("WEBUI_DISPLAY_TARGET_MULTIPLIER", "1.05")
)

WEBUI_HOST = os.environ.get("WEBUI_HOST", "0.0.0.0")
WEBUI_PORT = int(os.environ.get("WEBUI_PORT", "5001"))
WEBUI_DEBUG = os.environ.get("WEBUI_DEBUG", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# User QoS configuration: 2 High + 3 Medium + 5 Low
# Stable official-source profile
# High   (1-2):  GBR=0.8Gbps, MBR=1.2Gbps
# Medium (3-5):  GBR=0.4Gbps, MBR=0.8Gbps
# Low    (6-10): GBR=0.2Gbps, MBR=0.4Gbps

# Get hostname
HOSTNAME = socket.gethostname()
CLASS_LINE_RE = re.compile(r'^class\s+\S+\s+([0-9a-fA-F]+:[0-9a-fA-F]+)\b')
SENT_LINE_RE = re.compile(
    r'Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt(?:.*?\(dropped\s+(\d+),.*)?',
    re.IGNORECASE,
)


def load_upf_config():
    """Load UPF configuration file"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"Error loading config: {e}")
        return None


def bool_to_onoff(value):
    """Convert boolean or string to on/off string"""
    if isinstance(value, bool):
        return 'on' if value else 'off'
    elif isinstance(value, str):
        val_lower = value.lower()
        if val_lower in ['true', 'yes', '1', 'on']:
            return 'on'
        elif val_lower in ['false', 'no', '0', 'off']:
            return 'off'
        return val_lower
    else:
        return 'off'


def get_interface_ip(interface_name):
    """Get IP address of network interface"""
    try:
        cmd = f"ip -4 addr show {interface_name} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}'"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception as e:
        print(f"Error getting IP for interface {interface_name}: {e}")
    return 'N/A'


def load_sessions():
    """Load user session information"""
    try:
        if os.path.exists(SESSIONS_FILE):
            with open(SESSIONS_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        print(f"Error loading sessions: {e}")
        return []


def get_user_qos_tier(user_id):
    """Get QoS tier configuration based on user ID (10 users version)"""
    if 1 <= user_id <= 2:
        # High: 2 users
        return {"tier": "HIGH", "gbr": 0.8, "mbr": 1.2, "qfi": 1, "precedence": 10}
    elif 3 <= user_id <= 5:
        # Medium: 3 users
        return {"tier": "MEDIUM", "gbr": 0.4, "mbr": 0.8, "qfi": 5, "precedence": 50}
    else:
        # Low: 5 users (6-10)
        return {"tier": "LOW", "gbr": 0.2, "mbr": 0.4, "qfi": 9, "precedence": 100}


def is_upf_running():
    """Check if UPF process is running"""
    try:
        # Check if upf related process is running
        # Match: oai_upf, upf_app, upf, or executables containing upf
        cmd = "ps aux | grep -iE 'upf|oai-upf' | grep -v python | grep -v grep | grep -v tail | head -1"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=5)
        is_running = result.returncode == 0 and result.stdout.strip() != ""
        if is_running:
            # print(f"[DEBUG] UPF process found: {result.stdout.strip()[:80]}")
            return True
        return False
    except Exception as e:
        print(f"Error checking UPF process: {e}")
    return False


def has_active_upf_sessions():
    """Check if there are active UPF sessions (UPF process must be running and have PFCP session configuration)"""
    # First check if UPF process is running
    if not is_upf_running():
        # print("[DEBUG] UPF process not running")
        return False

    # Check multiple maps to confirm real active sessions
    # 1. QoS flow rate config - written when PFCP session is established
    # 2. m_session_pdrs - PDR rules (written when PFCP session is established)
    # Both maps must have data to consider sessions as active

    rate_config_id = find_any_bpf_map_id([
        "m_qos_flow_rate_config",
        "m_teid_rate_config"
    ])
    session_pdrs_id = find_bpf_map_id("m_session_pdrs")

    rate_config_count = 0
    session_pdrs_count = 0

    # Check QoS flow rate config
    if rate_config_id is not None:
        try:
            cmd = f"sudo bpftool map dump id {rate_config_id} -j"
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, timeout=5)
            if result.returncode == 0:
                entries = json.loads(result.stdout)
                rate_config_count = len(entries)
        except Exception as e:
            print(f"Error checking QoS flow rate config map: {e}")

    # Check m_session_pdrs
    if session_pdrs_id is not None:
        try:
            cmd = f"sudo bpftool map dump id {session_pdrs_id} -j"
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, timeout=5)
            if result.returncode == 0:
                entries = json.loads(result.stdout)
                session_pdrs_count = len(entries)
                # print(f"[DEBUG] m_session_pdrs has {session_pdrs_count} entries")
        except Exception as e:
            print(f"Error checking m_session_pdrs: {e}")

    if session_pdrs_count > 0:
        return True

    if rate_config_count > 0:
        return True

    config = load_upf_config()
    n3_iface = (
        config.get('nfs', {}).get('upf', {}).get('n3', {}).get('interface_name', 'N/A')
        if config else "N/A"
    )

    if n3_iface and n3_iface != "N/A":
        try:
            cmd = f"sudo tc class show dev {n3_iface}"
            result = subprocess.run(
                cmd, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=5
            )
            if result.returncode == 0:
                class_lines = [
                    line for line in result.stdout.splitlines()
                    if line.strip().startswith("class htb 1:")
                ]
                if len(class_lines) > 1:
                    return True
        except Exception as e:
            print(f"Error checking HTB classes on {n3_iface}: {e}")

    return False


def find_bpf_map_id(map_name):
    """Find BPF map ID (supports prefix matching since BPF map names are limited to 15 characters)"""
    try:
        cmd = "sudo bpftool map list -j"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=5)
        if result.returncode != 0:
            print(f"[DEBUG] bpftool map list failed: {result.stderr}")
            return None

        maps = json.loads(result.stdout)
        # BPF map names are limited to 15 characters, so use prefix matching
        search_prefix = map_name[:15] if len(map_name) > 15 else map_name
        matches = []
        for m in maps:
            actual_name = m.get("name", "")
            if actual_name == search_prefix or actual_name.startswith(search_prefix[:15]):
                map_id = m.get("id")
                if map_id is not None:
                    matches.append(map_id)
        if matches:
            return max(matches)
    except Exception as e:
        print(f"Error finding BPF map: {e}")
    return None


def find_any_bpf_map_id(map_names):
    """Find the first available BPF map from a list of preferred names."""
    for map_name in map_names:
        map_id = find_bpf_map_id(map_name)
        if map_id is not None:
            return map_id
    return None


def decode_bpf_byte_array(raw_bytes):
    """Decode bpftool JSON byte arrays into bytes."""
    if not isinstance(raw_bytes, list):
        return None
    try:
        return bytes(
            int(x, 16) if isinstance(x, str) else x
            for x in raw_bytes
        )
    except Exception:
        return None


def decode_qos_flow_key(key_bytes):
    """Decode either the new QoS-flow key (SEID + QFI) or the legacy u32 key."""
    if not key_bytes:
        return None, None

    if len(key_bytes) >= 16:
        seid = struct.unpack("<Q", key_bytes[:8])[0]
        qfi = key_bytes[8]
        return seid, qfi

    if len(key_bytes) >= 4:
        legacy_key = struct.unpack("<I", key_bytes[:4])[0]
        return legacy_key, None

    return None, None


def generate_minor_id(seid, qfi):
    """Mirror the upstream helper used by official HTB-based TC classes."""
    hash_value = (seid ^ (seid >> 16) ^ (seid >> 32) ^ (seid >> 48)) & 0xFFFF
    minor_id = (hash_value + (qfi * 37)) & 0xFFFF
    if minor_id > 9999:
        minor_id = 9999
    return minor_id or 1


def empty_runtime_stats(sessions):
    """Build the default runtime stats structure."""
    return {
        session["user_id"]: {
            "bytes_passed": 0,
            "bytes_dropped": 0,
            "pkts_passed": 0,
            "pkts_dropped": 0,
            "drop_metrics_available": False
        }
        for session in sessions
    }


def get_bpf_stats(sessions):
    """Get BPF statistics and aggregate them back to each logical user session."""
    user_stats = empty_runtime_stats(sessions)

    map_id = find_any_bpf_map_id([
        "m_qos_flow_stats",
        "m_teid_stats"
    ])
    if map_id is None:
        return user_stats

    seid_to_user = {
        int(session.get("seid", session["user_id"])): session["user_id"]
        for session in sessions
    }

    try:
        cmd = f"sudo bpftool map dump id {map_id} -j"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=5)
        if result.returncode != 0:
            return user_stats

        entries = json.loads(result.stdout)
        for entry in entries:
            key_bytes = decode_bpf_byte_array(entry.get("key", []))
            if not key_bytes:
                continue

            seid, _ = decode_qos_flow_key(key_bytes)
            if seid is None:
                continue

            user_id = seid_to_user.get(seid)
            if user_id is None and 1 <= seid <= NUM_USERS:
                user_id = int(seid)
            if user_id is None:
                continue

            value_bytes = decode_bpf_byte_array(entry.get("value", []))
            if not value_bytes or len(value_bytes) < 32:
                continue

            stats = struct.unpack("<QQQQ", value_bytes[:32])
            user_stats[user_id]["bytes_passed"] += stats[0]
            user_stats[user_id]["bytes_dropped"] += stats[1]
            user_stats[user_id]["pkts_passed"] += stats[2]
            user_stats[user_id]["pkts_dropped"] += stats[3]
            user_stats[user_id]["drop_metrics_available"] = True
    except Exception as e:
        print(f"Error getting BPF stats: {e}")

    return user_stats


def get_tc_class_stats(iface, sessions):
    """Read per-user runtime counters from official HTB classes on N3."""
    user_stats = empty_runtime_stats(sessions)
    if not iface or iface == "N/A":
        return user_stats, False, 0

    class_to_user = {}
    for session in sessions:
        seid = parse_int(session.get("seid"), session["user_id"])
        qfi = parse_int(session.get("qfi"), 0)
        class_to_user[f"1:{generate_minor_id(seid, qfi):x}".lower()] = session["user_id"]

    matched_classes = 0
    current_user_id = None
    aggregate_bytes = 0

    try:
        cmd = f"sudo tc -s class show dev {iface}"
        result = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=5
        )
        if result.returncode != 0 or not result.stdout.strip():
            return user_stats, False, 0

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            class_match = CLASS_LINE_RE.match(line)
            if class_match:
                current_user_id = class_to_user.get(class_match.group(1).lower())
                if current_user_id is not None:
                    matched_classes += 1
                continue

            if current_user_id is None:
                continue

            sent_match = SENT_LINE_RE.search(line)
            if not sent_match:
                continue

            user_stats[current_user_id]["bytes_passed"] = int(sent_match.group(1))
            user_stats[current_user_id]["pkts_passed"] = int(sent_match.group(2))
            user_stats[current_user_id]["pkts_dropped"] = int(sent_match.group(3) or 0)
            user_stats[current_user_id]["drop_metrics_available"] = True
            aggregate_bytes += int(sent_match.group(1))
            current_user_id = None

    except Exception as e:
        print(f"Error getting TC class stats: {e}")
        return user_stats, False, 0

    return user_stats, matched_classes > 0, aggregate_bytes


def get_runtime_stats_mode(n3_iface, sessions):
    """Pick the best available runtime statistics source for the current UPF mode."""
    bpf_map_id = find_any_bpf_map_id([
        "m_qos_flow_stats",
        "m_teid_stats"
    ])
    if bpf_map_id is not None:
        return get_bpf_stats(sessions), "bpf_map", True, None

    tc_stats, tc_available, tc_aggregate_bytes = get_tc_class_stats(n3_iface, sessions)
    if tc_available:
        return tc_stats, "official_htb", True, tc_aggregate_bytes

    return empty_runtime_stats(sessions), "configured_only", False, None


def build_rate_basis(stats_mode):
    """Describe how runtime rates should be interpreted in the UI."""
    if stats_mode == "bpf_map":
        return {
            "measured_label": "BPF charged bytes after GTP encapsulation",
            "configured_label": "PFCP GBR/MBR business rates",
            "display_label": "Expected range on the same BPF-charged basis",
            "target_multiplier": DISPLAY_TARGET_MULTIPLIER
        }

    if stats_mode == "tc_htb":
        return {
            "measured_label": "Aggregate N3 traffic with official upstream HTB classes active",
            "configured_label": "PFCP GBR/MBR values applied to HTB classes",
            "display_label": "Per-user runtime counters are not exported in official mode; the table shows configured session targets only",
            "target_multiplier": 1.0
        }

    if stats_mode == "official_htb":
        return {
            "measured_label": "Per-user runtime rates derived from official HTB class counters on N3",
            "configured_label": "PFCP GBR/MBR values applied to HTB classes",
            "display_label": "Expected ranges are compared directly against HTB class accounting",
            "target_multiplier": 1.0
        }

    return {
        "measured_label": "Per-user runtime counters unavailable in official UPF mode",
        "configured_label": "PFCP GBR/MBR configured session targets",
        "display_label": "Configured session profile",
        "target_multiplier": 1.0
    }


def get_interface_stats(iface):
    """Get network interface statistics"""
    try:
        rx_path = f"/sys/class/net/{iface}/statistics/rx_bytes"
        tx_path = f"/sys/class/net/{iface}/statistics/tx_bytes"

        with open(rx_path, 'r') as f:
            rx = int(f.read().strip())
        with open(tx_path, 'r') as f:
            tx = int(f.read().strip())
        return rx, tx
    except Exception as e:
        return 0, 0


# ==================== API Routes ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check"""
    return jsonify({"status": "ok", "timestamp": time.time()})


@app.route('/api/upf/config', methods=['GET'])
def get_upf_config():
    """Get UPF configuration information"""
    config = load_upf_config()
    if config is None:
        return jsonify({"error": "Failed to load config"}), 500

    # Extract key configuration
    upf_config = config.get('upf', {})
    nfs_upf = config.get('nfs', {}).get('upf', {})

    # Get interface configuration and add hostname and IP information
    n3_config = nfs_upf.get('n3', {})
    n4_config = nfs_upf.get('n4', {})
    n6_config = nfs_upf.get('n6', {})
    upf_host = nfs_upf.get('host', 'N/A')

    # Get actual IP address for each interface
    n3_iface = n3_config.get('interface_name', 'N/A')
    n4_iface = n4_config.get('interface_name', 'N/A')
    n6_iface = n6_config.get('interface_name', 'N/A')

    n3_ip = get_interface_ip(n3_iface) if n3_iface != 'N/A' else 'N/A'
    n4_ip = get_interface_ip(n4_iface) if n4_iface != 'N/A' else 'N/A'
    n6_ip = get_interface_ip(n6_iface) if n6_iface != 'N/A' else 'N/A'

    # Get support_features, ensure correct parsing of boolean values
    support_features = upf_config.get('support_features', {})

    result = {
        "timestamp": time.time(),
        "hostname": HOSTNAME,
        "host_ip": upf_host,
        "support_features": {
            "enable_bpf_datapath": bool_to_onoff(support_features.get('enable_bpf_datapath', False)),
            "enable_qos": bool_to_onoff(support_features.get('enable_qos', False)),
            "enable_snat": bool_to_onoff(support_features.get('enable_snat', False)),
            "qdisc_scheduler": support_features.get('qdisc_scheduler', 'htb'),
            "max_pdrs_per_pdu_session": support_features.get('max_pdrs_per_pdu_session', 'N/A')
        },
        "interfaces": {
            "n3": {
                "hostname": HOSTNAME,
                "interface_name": n3_iface,
                "port": n3_config.get('port', 'N/A'),
                "ip_address": n3_ip
            },
            "n4": {
                "hostname": HOSTNAME,
                "interface_name": n4_iface,
                "port": n4_config.get('port', 'N/A'),
                "ip_address": n4_ip
            },
            "n6": {
                "hostname": HOSTNAME,
                "interface_name": n6_iface,
                "ip_address": n6_ip
                # N6 is data plane interface, no port number needed
            }
        },
        "remote_n6_gw": upf_config.get('remote_n6_gw', ''),
        "log_level": config.get('log_level', {}),
        "http_version": config.get('http_version', 2)
    }

    return jsonify(result)


def get_user_ip(user_id):
    """Get IP address based on user ID (10 users version)"""
    # Users 1-10 correspond to IP 12.1.1.2 - 12.1.1.11
    return f"12.1.1.{user_id + 1}"


def parse_int(value, default):
    """Parse decimal or hex-like integers from persisted session metadata."""
    if value is None:
        return default
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def build_default_sessions():
    """Build the default 10-user session layout."""
    sessions = []
    for i in range(1, NUM_USERS + 1):
        qos = get_user_qos_tier(i)
        sessions.append({
            "user_id": i,
            "seid": i,
            "user_ip": get_user_ip(i),
            "teid": hex(TEID_BASE + i - 1),
            "qos_tier": qos["tier"],
            "gbr_gbps": qos["gbr"],
            "mbr_gbps": qos["mbr"],
            "qfi": qos["qfi"],
            "precedence": qos["precedence"],
            "status": "configured"
        })
    return sessions


def normalize_session_entry(entry, fallback_user_id):
    """Normalize session records loaded from disk."""
    qos = get_user_qos_tier(fallback_user_id)
    user_id = parse_int(entry.get("user_id"), fallback_user_id)
    return {
        "user_id": user_id,
        "seid": parse_int(entry.get("seid"), user_id),
        "user_ip": entry.get("user_ip", get_user_ip(user_id)),
        "teid": entry.get("teid", hex(TEID_BASE + user_id - 1)),
        "qos_tier": entry.get("qos_tier", qos["tier"]),
        "gbr_gbps": float(entry.get("gbr_gbps", qos["gbr"])),
        "mbr_gbps": float(entry.get("mbr_gbps", qos["mbr"])),
        "qfi": parse_int(entry.get("qfi"), qos["qfi"]),
        "precedence": parse_int(entry.get("precedence"), qos["precedence"]),
        "status": entry.get("status", "configured")
    }


def get_effective_sessions():
    """Use saved session metadata when available, otherwise fall back to the default layout."""
    sessions = load_sessions()
    if not sessions:
        return build_default_sessions()

    normalized = []
    for index, entry in enumerate(sessions, start=1):
        if isinstance(entry, dict):
            normalized.append(normalize_session_entry(entry, index))
    return normalized


@app.route('/api/users/sessions', methods=['GET'])
def get_user_sessions():
    """Get user session information"""
    # Check if there are active UPF sessions (UPF process running and BPF map exists)
    has_active_sessions = has_active_upf_sessions()

    if has_active_sessions:
        sessions = get_effective_sessions()
        if not sessions:
            sessions = build_default_sessions()
    else:
        sessions = []

    return jsonify({
        "timestamp": time.time(),
        "total_users": len(sessions) if sessions else 0,
        "sessions": sessions if sessions else [],
        "has_active_sessions": has_active_sessions
    })


@app.route('/api/stats/realtime', methods=['GET'])
def get_realtime_stats():
    """Get real-time statistics"""
    # Check if there are active UPF sessions
    has_active_sessions = has_active_upf_sessions()
    sessions = get_effective_sessions() if has_active_sessions else []
    # Get N3 and N6 interface statistics
    config = load_upf_config()
    n3_iface = "N/A"
    n6_iface = "N/A"

    if config:
        n3_iface = config.get('nfs', {}).get('upf', {}).get('n3', {}).get('interface_name', 'N/A')
        n6_iface = config.get('nfs', {}).get('upf', {}).get('n6', {}).get('interface_name', 'N/A')

    # Get N3 interface statistics (uplink traffic)
    n3_rx_bytes, n3_tx_bytes = get_interface_stats(n3_iface)

    # Get N6 interface statistics (downlink traffic)
    n6_rx_bytes, n6_tx_bytes = get_interface_stats(n6_iface)

    runtime_stats, stats_mode, per_user_stats_available, runtime_aggregate_bytes = (
        get_runtime_stats_mode(n3_iface, sessions) if sessions else ({}, "configured_only", False, None)
    )
    rate_basis = build_rate_basis(stats_mode)
    display_multiplier = rate_basis["target_multiplier"]

    # Assemble user statistics - only return user data when there are active sessions
    user_stats = []
    total_bytes_passed = 0
    total_bytes_dropped = 0

    if has_active_sessions:
        for session in sessions:
            user_id = session["user_id"]
            stats = runtime_stats.get(user_id, {})

            bytes_passed = stats.get("bytes_passed", 0)
            bytes_dropped = stats.get("bytes_dropped", 0)
            pkts_passed = stats.get("pkts_passed", 0)
            pkts_dropped = stats.get("pkts_dropped", 0)
            drop_metrics_available = stats.get("drop_metrics_available", False)

            total_bytes = bytes_passed + (bytes_dropped or 0)
            drop_rate = (
                round(bytes_dropped / total_bytes * 100, 2)
                if drop_metrics_available and total_bytes > 0
                else None
            )

            total_bytes_passed += bytes_passed
            total_bytes_dropped += bytes_dropped or 0

            user_stats.append({
                "user_id": user_id,
                "user_ip": session["user_ip"],
                "qos_tier": session["qos_tier"],
                "bytes_passed": bytes_passed,
                "bytes_dropped": bytes_dropped if drop_metrics_available else None,
                "pkts_passed": pkts_passed,
                "pkts_dropped": pkts_dropped,
                "drop_rate_percent": drop_rate,
                "drop_metrics_available": drop_metrics_available,
                "configured_gbr_gbps": session["gbr_gbps"],
                "configured_mbr_gbps": session["mbr_gbps"],
                "target_gbr_gbps": round(
                    session["gbr_gbps"] * display_multiplier, 2
                ),
                "target_mbr_gbps": round(
                    session["mbr_gbps"] * display_multiplier, 2
                ),
                "stats_available": per_user_stats_available
            })

    if stats_mode == "official_htb" and not per_user_stats_available:
        total_bytes_passed = runtime_aggregate_bytes or 0
        total_bytes_dropped = 0

    return jsonify({
        "timestamp": time.time(),
        "hostname": HOSTNAME,
        "stats_mode": stats_mode,
        "per_user_stats_available": per_user_stats_available,
        "rate_basis": rate_basis,
        "interfaces": {
            "n3": {
                "name": n3_iface,
                "rx_bytes": n3_rx_bytes,
                "tx_bytes": n3_tx_bytes
            },
            "n6": {
                "name": n6_iface,
                "rx_bytes": n6_rx_bytes,
                "tx_bytes": n6_tx_bytes
            }
        },
        "bpf_stats": {
            "total_bytes_passed": total_bytes_passed,
            "total_bytes_dropped": total_bytes_dropped
        },
        "users": user_stats
    })


@app.route('/api/stats/rates', methods=['GET'])
def get_rate_stats():
    """Get rate statistics (requires client to calculate difference)"""
    return get_realtime_stats()


@app.route('/api/qos/analysis', methods=['GET'])
def get_qos_analysis():
    """
    Get QoS achievement analysis
    """
    sessions = get_effective_sessions()
    if not sessions:
        sessions = build_default_sessions()

    total_gbr = sum(session["gbr_gbps"] for session in sessions)
    total_mbr = sum(session["mbr_gbps"] for session in sessions)
    config = load_upf_config()
    n3_iface = "N/A"
    if config:
        n3_iface = config.get('nfs', {}).get('upf', {}).get('n3', {}).get('interface_name', 'N/A')
    _, stats_mode, per_user_runtime_available, _ = get_runtime_stats_mode(n3_iface, sessions)
    rate_basis = build_rate_basis(stats_mode)
    display_total_gbr = total_gbr * rate_basis["target_multiplier"]
    display_total_mbr = total_mbr * rate_basis["target_multiplier"]
    max_bandwidth = 100.0  # 100 Gbps

    # Calculate resource utilization
    gbr_utilization = (total_gbr / max_bandwidth) * 100
    mbr_utilization = (total_mbr / max_bandwidth) * 100

    # Statistics by tier
    tier_stats = {}
    for session in sessions:
        tier = session["qos_tier"]
        if tier not in tier_stats:
            tier_stats[tier] = {
                "count": 0,
                "gbr": session["gbr_gbps"],
                "mbr": session["mbr_gbps"],
                "total_gbr": 0.0,
                "total_mbr": 0.0
            }
        tier_stats[tier]["count"] += 1
        tier_stats[tier]["total_gbr"] += session["gbr_gbps"]
        tier_stats[tier]["total_mbr"] += session["mbr_gbps"]

    return jsonify({
        "timestamp": time.time(),
        "config": {
            "total_users": len(sessions),
            "max_bandwidth_gbps": max_bandwidth,
            "total_gbr_gbps": round(total_gbr, 2),
            "total_mbr_gbps": round(total_mbr, 2),
            "display_total_gbr_gbps": round(display_total_gbr, 2),
            "display_total_mbr_gbps": round(display_total_mbr, 2),
            "gbr_utilization_percent": round(gbr_utilization, 1),
            "mbr_utilization_percent": round(mbr_utilization, 1),
            "headroom_gbps": round(max_bandwidth - total_gbr, 1)
        },
        "tier_stats": tier_stats,
        "rate_basis": rate_basis,
        "per_user_runtime_available": per_user_runtime_available,
        "qos_metrics": {
            "description": "QoS achievement metrics",
            "gbr_satisfaction": {
                "name": "GBR Satisfaction Rate",
                "formula": "Percentage of samples where actual rate >= GBR",
                "weight": 0.7,
                "thresholds": {
                    "excellent": ">= 99%",
                    "good": ">= 95%",
                    "acceptable": ">= 90%",
                    "poor": "< 90%"
                }
            },
            "mbr_compliance": {
                "name": "MBR Compliance Rate",
                "formula": "Percentage of samples where actual rate <= MBR",
                "weight": 0.3,
                "thresholds": {
                    "excellent": ">= 99%",
                    "good": ">= 95%",
                    "acceptable": ">= 90%",
                    "poor": "< 90%"
                }
            },
            "overall_score": {
                "name": "Overall Achievement",
                "formula": "(GBR Satisfaction Rate x 0.7) + (MBR Compliance Rate x 0.3)"
            }
        },
        "scenarios": {
            "resource_sufficient": {
                "description": "Resource sufficient scenario (total traffic <= 6.8Gbps)",
                "expected_gbr_satisfaction": "100%",
                "expected_mbr_compliance": "100%",
                "note": "All users can get their GBR guaranteed bandwidth"
            },
            "resource_constrained": {
                "description": "Resource constrained scenario (total traffic > 6.8Gbps)",
                "priority_order": ["HIGH", "MEDIUM", "LOW"],
                "strategy": "Prioritize high priority users, low priority users are rate-limited",
                "note": "Official upstream HTB classes enforce the configured session limits"
            }
        }
    })


# Static file serving (frontend pages)
@app.route('/')
def index():
    """Serve frontend page"""
    frontend_dir = os.path.join(os.path.dirname(__file__), "../frontend")
    return send_from_directory(frontend_dir, 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    frontend_dir = os.path.join(os.path.dirname(__file__), "../frontend")
    return send_from_directory(frontend_dir, path)


if __name__ == '__main__':
    # Ensure data directory exists
    data_dir = os.path.join(os.path.dirname(__file__), "../data")
    os.makedirs(data_dir, exist_ok=True)

    print("=" * 60)
    print("OAI-UPF Web Monitoring Server Started")
    print("=" * 60)
    print(f"Config file: {CONFIG_FILE}")
    print(f"Session data: {SESSIONS_FILE}")
    print(f"Access URL: http://{WEBUI_HOST}:{WEBUI_PORT}")
    print("=" * 60)

    app.run(host=WEBUI_HOST, port=WEBUI_PORT, debug=WEBUI_DEBUG)
