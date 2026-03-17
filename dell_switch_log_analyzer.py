#!/usr/bin/env python3
"""
Dell Switch Log Analyzer for Dynatrace
=======================================
Generic tool to ingest Dell switch syslog files into Dynatrace and
auto-generate a Gen 3 comprehensive analysis dashboard.

Supports:
  - Dell N-Series (N3048ET, N3048ET-ON, etc.) - BSD syslog format
  - Dell OS10 (S4128T-ON, S5248F-ON, etc.) - RFC5424 syslog format
  - Auto-discovers switch IPs, hostnames, and models from log content
  - Auto-detects ingestion timeframe for dashboard queries

Analysis Covers:
  - STP: root bridge changes, topology changes, port state transitions, BPDU
  - Interface: link up/down, flapping, admin state changes
  - Auth/Access: user logins, session events, password changes
  - Performance: CPU utilization alarms, process utilization
  - LACP/LAG: port grouped/ungrouped, link aggregation changes
  - VLT: peer up/down, role elections, port-channel state
  - Hardware: fan/PSU/unit detection, SFP changes, faults
  - System: restarts, disk space, mode changes, MAC moves

Usage:
  # Set environment variables:
  #   DT_ENV_URL     - Dynatrace environment URL (e.g. https://abc12345.live.dynatrace.com)
  #   DT_API_TOKEN   - Dynatrace API token with "logs.ingest" scope (for data ingestion)
  #   DT_OAUTH_CLIENT_ID - OAuth client ID (default: dt0s12.local-dt-mcp-server)

  # Ingest only:
  py dell_switch_log_analyzer.py ingest <path_to_logs>

  # Dashboard only (after ingestion):
  py dell_switch_log_analyzer.py dashboard

  # Full pipeline (ingest + analyze + dashboard):
  py dell_switch_log_analyzer.py all <path_to_logs>

  <path_to_logs> can be a .zip file or a directory containing .txt/.log files.
"""

import re
import json
import os
import sys
import time
import uuid
import hashlib
import base64
import secrets
import zipfile
import webbrowser
import urllib.parse
import threading
import argparse
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# =============================================================================
#  Configuration (all from environment variables, no hardcoding)
# =============================================================================
def get_config():
    dt_env_url = os.environ.get("DT_ENV_URL", "").rstrip("/")
    if not dt_env_url:
        print("ERROR: DT_ENV_URL environment variable not set.")
        print("  Set it to your Dynatrace environment URL, e.g.:")
        print("  $env:DT_ENV_URL = 'https://abc12345.live.dynatrace.com'")
        sys.exit(1)

    # Derive API URL from apps URL or use directly
    # e.g. https://abc.apps.dynatrace.com -> https://abc.dynatrace.com for API
    # or user provides the API URL directly
    api_url = os.environ.get("DT_API_URL", "")
    if not api_url:
        # Try to derive: *.apps.* -> remove .apps
        api_url = re.sub(r'\.apps\.', '.', dt_env_url)
        # Also handle sprint labs format
        api_url = re.sub(r'\.sprint\.apps\.', '.sprint.', api_url)

    return {
        "env_url": dt_env_url,
        "api_url": api_url,
        "api_token": os.environ.get("DT_API_TOKEN", ""),
        "oauth_client_id": os.environ.get("DT_OAUTH_CLIENT_ID", "dt0s12.local-dt-mcp-server"),
        "redirect_port": int(os.environ.get("DT_OAUTH_PORT", "5344")),
        "batch_size": int(os.environ.get("DT_BATCH_SIZE", "1000")),
    }


# =============================================================================
#  Syslog Parsing (generic, auto-discovers switch info from log content)
# =============================================================================

SYSLOG_SEVERITY = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"
}

STP_KEYWORDS = re.compile(
    r'STP|Spanning.?Tree|RSTP|RPVST|BPDU|dot1s|topology.change|TCN|'
    r'root.bridge|root.change|STP_ROOT|STP_COMPAT|port.state|MSTP',
    re.IGNORECASE
)

# Event category classification for OS10 event codes
EVENT_CATEGORIES = {
    # STP
    'STP_ROOT_CHANGE': 'stp', 'STP_COMPATIBILITY_MODE': 'stp',
    # Interface
    'IFM_OSTATE_UP': 'interface', 'IFM_OSTATE_DN': 'interface',
    'IFM_ASTATE_UP': 'interface', 'IFM_ASTATE_DN': 'interface',
    # Auth
    'ALM_AUTH_EVENT': 'auth', 'PASSWORD_CHANGE': 'auth',
    # Performance/CPU
    'PM_SYS_UTIL_HI': 'performance', 'PM_SYS_UTIL_LO': 'performance',
    'PM_PROC_UTIL_HI': 'performance', 'PM_PROC_UTIL_LO': 'performance',
    # LACP
    'LACP_PORT_GROUPED': 'lacp', 'LACP_PORT_UNGROUPED': 'lacp',
    # VLT
    'VLT_PORT_CHANNEL_UP': 'vlt', 'VLT_PORT_CHANNEL_DOWN': 'vlt',
    'VLT_PEER_UP': 'vlt', 'VLT_PEER_DOWN': 'vlt',
    'VLT_ELECTION_ROLE': 'vlt', 'VLT_DELAY_RESTORE_START': 'vlt',
    'VLT_DELAY_RESTORE_COMPLETE': 'vlt',
    # Hardware
    'EQM_FAN_TRAY_DETECTED': 'hardware', 'EQM_PSU_DETECTED': 'hardware',
    'EQM_MORE_PSU_FAULT': 'hardware', 'EQM_UNIT_DETECTED': 'hardware',
    'EQM_UNIT_CHECKIN': 'hardware', 'EQM_UNIT_UP': 'hardware',
    'EQM_MEDIA_PRESENT': 'hardware', 'EQM_MEDIA_NOT_PRESENT': 'hardware',
    # System
    'SYS_STAT_LOW_DISK_SPACE': 'system', 'SYSTEM_MODE_CHNG': 'system',
    'ALM_SYSTEM_RESTART': 'system', 'NDM_SYSTEM_RELOAD': 'system',
    'INFRA_AFS': 'system', 'CMS_INIT_STATE': 'system',
    'SUPPORT_BUNDLE_STARTED': 'system', 'SUPPORT_BUNDLE_COMPLETED': 'system',
    'SOSREPORT_GEN_STARTED': 'system',
}

# BSD syslog process-to-category mapping
BSD_PROCESS_CATEGORIES = {
    'TRAPMGR': None,  # classified by message content
    'FDB': 'system',  # MAC moves
    'CLI_WEB': 'auth',
    'DOT3AD': 'lacp',
    'OpEN': 'system',  # SupportAssist
}

# N-Series BSD syslog: <priority>Mon DD HH:MM:SS hostname process[task]: file(line) seq %% LEVEL msg
BSD_SYSLOG = re.compile(
    r'^<(\d+)>\s*'
    r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(\S+)\s+'
    r'(\w+)\[([^\]]+)\]:\s+'
    r'(\S+)\s+'
    r'(\d+)\s+'
    r'%%\s+(\w+)\s+'
    r'(.+)$'
)

# OS10 RFC5424: <priority>1 ISO-timestamp hostname app pid - - message
RFC5424_SYSLOG = re.compile(
    r'^<(\d+)>1\s+'
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+\-]\d{2}:\d{2})\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'(\d+)\s+'
    r'-\s+-\s+'
    r'(.+)$'
)

# Skip lines matching these patterns (non-log content)
SKIP_PREFIXES = [
    '=~=', 'login as:', '|', 'Pre-auth', 'End of banner',
    'NSDL', 'Linux ', 'The programs', 'individual', 'Debian', '-*-',
    'This product', 'intellectual', 'jurisdiction', 'trademarks', '%Warning',
    'terminal length', ' ---', 'Dell Smart', 'Copyright', 'OS Version',
    'Build ', 'System Type', 'Architecture', 'Up Time', 'Ethernet ',
    'Description', 'Hardware', '    Current', 'Pluggable', '    Wavelength',
    '    Configured', 'Interface index', 'Internet', 'Mode of',
    '    Interface IPv', 'IP Unreachables', 'MTU ', 'LineSpeed',
    'Flowcontrol', 'ARP type', 'Tag Protocol', 'Last clearing',
    'Queuing', 'Input statistics', 'Output statistics', 'Logging is',
    'Logging protocol', 'Source Interface', 'Console Logging',
    'Monitor Logging', 'Buffer Logging', 'File Logging', 'Switch Auditing',
    'CLI Command', 'Web Session', 'SNMP Set', 'Logging facility',
    'Syslog ', 'Buffer Log', '<cr>', 'show ', 'email ', 'file '
]


def infer_switch_info_from_filename(filename):
    """Extract switch IP from filename like '10.150.1.4.txt' or '10.150.1.7_Old.txt'."""
    m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', filename)
    if m:
        return m.group(1)
    return None


def detect_model_from_hostname(hostname):
    """Infer Dell model from hostname pattern."""
    hn = hostname.lower()
    # Common Dell OS10 hostnames
    if any(x in hn for x in ['s4128', 's5148', 's5248', 's5296', 's6100', 'os10']):
        return "OS10-Series"
    if any(x in hn for x in ['n3048', 'n2048', 'n1548', 'n1524', 'n2024', 'n3024', 'n4064']):
        return "N-Series"
    return "Dell-Switch"


def parse_bsd_syslog_line(line, year=None):
    if year is None:
        year = str(datetime.now().year)
    m = BSD_SYSLOG.match(line.strip())
    if not m:
        return None
    priority = int(m.group(1))
    severity_num = priority % 8
    ts_str = m.group(2)
    try:
        ts = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        ts = ts.replace(tzinfo=timezone.utc)
        timestamp = ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        timestamp = None
    return {
        "timestamp": timestamp,
        "hostname": m.group(3),
        "process": m.group(4),
        "task": m.group(5),
        "source_file_ref": m.group(6),
        "sequence": m.group(7),
        "severity": SYSLOG_SEVERITY.get(severity_num, "INFO"),
        "severity_num": severity_num,
        "facility": priority // 8,
        "level": m.group(8),
        "message": m.group(9).strip(),
        "format": "bsd_syslog"
    }


def parse_rfc5424_line(line):
    m = RFC5424_SYSLOG.match(line.strip())
    if not m:
        return None
    priority = int(m.group(1))
    severity_num = priority % 8
    timestamp_raw = m.group(2)
    try:
        ts = datetime.fromisoformat(timestamp_raw)
        timestamp = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except ValueError:
        timestamp = timestamp_raw
    full_message = m.group(6).strip()
    event_type = None
    event_match = re.search(r'%(\w+):', full_message)
    if event_match:
        event_type = event_match.group(1)
    log_level_match = re.search(r'\[(\w+)\]', full_message)
    log_level = log_level_match.group(1) if log_level_match else "info"
    return {
        "timestamp": timestamp,
        "hostname": m.group(3),
        "app_name": m.group(4),
        "proc_id": m.group(5),
        "severity": SYSLOG_SEVERITY.get(severity_num, "INFO"),
        "severity_num": severity_num,
        "facility": priority // 8,
        "event_type": event_type,
        "log_level": log_level,
        "message": full_message,
        "format": "rfc5424"
    }


def classify_stp_event(message):
    msg_lower = message.lower()
    if "topology change received" in msg_lower:
        return "STP_TOPOLOGY_CHANGE_RECEIVED"
    elif "topology change" in msg_lower:
        return "STP_TOPOLOGY_CHANGE"
    elif "root" in msg_lower and "change" in msg_lower:
        return "STP_ROOT_BRIDGE_CHANGE"
    elif "compatibility mode" in msg_lower:
        return "STP_COMPATIBILITY_MODE"
    elif "bpdu" in msg_lower:
        return "STP_BPDU"
    elif "port state" in msg_lower or "forwarding" in msg_lower or "blocking" in msg_lower:
        return "STP_PORT_STATE_CHANGE"
    elif STP_KEYWORDS.search(message):
        return "STP_OTHER"
    return None


def classify_event_category(entry):
    """Classify an entry into an event category and sub-type. Returns (category, event_code)."""
    msg = entry.get("message", "")

    if entry.get("format") == "rfc5424":
        # OS10: use %EVENT_CODE from message
        ev_match = re.search(r'%([A-Z][A-Z0-9_]+):', msg)
        if ev_match:
            event_code = ev_match.group(1)
            category = EVENT_CATEGORIES.get(event_code)
            if not category:
                # Infer from prefix
                prefix = event_code.split('_')[0]
                prefix_map = {
                    'STP': 'stp', 'IFM': 'interface', 'ALM': 'auth',
                    'PM': 'performance', 'LACP': 'lacp', 'VLT': 'vlt',
                    'EQM': 'hardware', 'SYS': 'system', 'PIM': 'system',
                    'IP': 'system', 'ISCSI': 'system', 'NDM': 'system',
                    'UDS': 'system', 'CMS': 'system', 'INFRA': 'system',
                }
                category = prefix_map.get(prefix, 'other')
            return category, event_code
    else:
        # N-series BSD: classify by process + message content
        proc = entry.get("process", "")
        msg_lower = msg.lower()

        # STP events
        if STP_KEYWORDS.search(msg):
            return 'stp', classify_stp_event(msg) or 'STP_OTHER'

        # MAC moves (FDB)
        if 'MAC_MOVE' in msg:
            return 'system', 'FDB_MAC_MOVE'

        # Link events
        if 'Link Up' in msg:
            return 'interface', 'LINK_UP'
        if 'Link Down' in msg:
            return 'interface', 'LINK_DOWN'

        # Auth
        if proc == 'CLI_WEB' or 'logged in' in msg or 'Session' in msg_lower or 'password' in msg_lower:
            return 'auth', 'AUTH_LOGIN'

        # LACP
        if proc == 'DOT3AD' or 'attached to' in msg:
            return 'lacp', 'LACP_PORT_ATTACH'

        # SupportAssist
        if 'SUPPORT-ASSIST' in msg:
            return 'system', 'SUPPORT_ASSIST_ERROR'

        cat = BSD_PROCESS_CATEGORIES.get(proc, 'other')
        if cat:
            return cat, f'{proc}_EVENT'

    return 'other', 'UNKNOWN'


def extract_vlan_id(message):
    m = re.search(r'VLAN\s*(?:ID:?\s*)?(\d+)', message, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'vlan\s+(\d+)', message, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def extract_interface(message):
    m = re.search(r'((?:Po|Te|Gi|Fa|ethernet|port-channel|vlan)\d[\w/]*)', message, re.IGNORECASE)
    return m.group(1) if m else None


def extract_mac_address(message):
    m = re.search(
        r'(?:from\s+)?([0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})',
        message, re.IGNORECASE
    )
    return m.group(1) if m else None


def should_skip_line(line):
    if not line.strip():
        return True
    if 'password:' in line.lower():
        return True
    if re.match(r'^\s+[\d\s,e+.]+$', line):
        return True
    for prefix in SKIP_PREFIXES:
        if line.startswith(prefix):
            return True
    return False


def parse_log_file(filepath):
    """Parse a single log file. Auto-discovers switch IP from filename and hostname from content."""
    entries = []
    filename = filepath.name

    # Try to get IP from filename
    file_ip = infer_switch_info_from_filename(filename)

    # Track discovered info per file
    discovered_hostname = None
    discovered_model = None

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        buffer = ""
        for line in f:
            line = line.rstrip('\n\r')
            if should_skip_line(line):
                continue

            if line.startswith('<'):
                if buffer:
                    entry = parse_rfc5424_line(buffer) or parse_bsd_syslog_line(buffer)
                    if entry:
                        # Auto-discover from first parsed entry
                        if not discovered_hostname and entry.get("hostname"):
                            discovered_hostname = entry["hostname"]
                            discovered_model = detect_model_from_hostname(discovered_hostname)
                            if entry["format"] == "rfc5424":
                                discovered_model = "OS10-Series"
                            elif entry["format"] == "bsd_syslog":
                                discovered_model = "N-Series"

                        # Set switch info from auto-discovery
                        entry["switch_ip"] = file_ip or entry.get("hostname", "unknown")
                        entry["switch_model"] = discovered_model or "Dell-Switch"
                        entry["switch_hostname"] = entry.get("hostname", "")
                        entry["source_file"] = filename

                        # Classify event category
                        category, event_code = classify_event_category(entry)
                        entry["event_category"] = category
                        entry["event_code"] = event_code

                        is_stp = (category == 'stp') or bool(STP_KEYWORDS.search(entry["message"]))
                        entry["is_stp_related"] = is_stp
                        if is_stp:
                            entry["stp_event_type"] = classify_stp_event(entry["message"]) or event_code

                        # Extract enrichment from all events (not just STP)
                        entry["vlan_id"] = extract_vlan_id(entry["message"])
                        entry["interface"] = extract_interface(entry["message"])
                        entry["mac_address"] = extract_mac_address(entry["message"])

                        entries.append(entry)
                buffer = line
            else:
                buffer += " " + line.strip()

        # Last entry
        if buffer:
            entry = parse_rfc5424_line(buffer) or parse_bsd_syslog_line(buffer)
            if entry:
                entry["switch_ip"] = file_ip or entry.get("hostname", "unknown")
                entry["switch_model"] = discovered_model or "Dell-Switch"
                entry["switch_hostname"] = entry.get("hostname", "")
                entry["source_file"] = filename
                category, event_code = classify_event_category(entry)
                entry["event_category"] = category
                entry["event_code"] = event_code
                is_stp = (category == 'stp') or bool(STP_KEYWORDS.search(entry["message"]))
                entry["is_stp_related"] = is_stp
                if is_stp:
                    entry["stp_event_type"] = classify_stp_event(entry["message"]) or event_code
                entry["vlan_id"] = extract_vlan_id(entry["message"])
                entry["interface"] = extract_interface(entry["message"])
                entry["mac_address"] = extract_mac_address(entry["message"])
                entries.append(entry)

    return entries


def get_log_files(path):
    """Get log files from a directory or ZIP file."""
    path = Path(path)

    if path.suffix.lower() == '.zip':
        extract_dir = path.parent / path.stem
        if not extract_dir.exists():
            print(f"Extracting {path.name}...")
            with zipfile.ZipFile(path, 'r') as zf:
                zf.extractall(extract_dir)
        path = extract_dir

    if path.is_dir():
        files = []
        for ext in ('*.txt', '*.log', '*.syslog'):
            files.extend(path.glob(ext))
            files.extend(path.glob(f'**/{ext}'))  # recursive
        # Deduplicate and filter out scripts
        seen = set()
        result = []
        for f in sorted(files):
            if f.resolve() not in seen and f.suffix in ('.txt', '.log', '.syslog'):
                if not f.name.endswith('.py'):
                    seen.add(f.resolve())
                    result.append(f)
        return result
    elif path.is_file():
        return [path]
    else:
        print(f"ERROR: Path not found: {path}")
        sys.exit(1)


# =============================================================================
#  Dynatrace Ingestion
# =============================================================================

def convert_to_dynatrace_format(entry):
    dt_entry = {
        "content": entry["message"],
        "log.source": "dell-switch",
        "severity": entry.get("severity", "INFO"),
        "switch.ip": entry.get("switch_ip", ""),
        "switch.model": entry.get("switch_model", ""),
        "switch.hostname": entry.get("switch_hostname", ""),
        "stp.related": str(entry.get("is_stp_related", False)).lower(),
        "event.category": entry.get("event_category", "other"),
        "event.code": entry.get("event_code", "UNKNOWN"),
    }

    if entry.get("timestamp"):
        dt_entry["original.timestamp"] = entry["timestamp"]
    if entry.get("process"):
        dt_entry["process.name"] = entry["process"]
    if entry.get("event_type"):
        dt_entry["dell.event.type"] = entry["event_type"]
    if entry.get("app_name"):
        dt_entry["app.name"] = entry["app_name"]
    if entry.get("stp_event_type"):
        dt_entry["stp.event.type"] = entry["stp_event_type"]
    if entry.get("vlan_id"):
        dt_entry["vlan.id"] = entry["vlan_id"]
    if entry.get("interface"):
        dt_entry["interface.name"] = entry["interface"]
    if entry.get("mac_address"):
        dt_entry["mac.address"] = entry["mac_address"]

    return dt_entry


def ingest_to_dynatrace(entries, config):
    api_token = config["api_token"]
    if not api_token:
        print("ERROR: DT_API_TOKEN environment variable not set.")
        print("  Set it to a Dynatrace API token with 'logs.ingest' scope.")
        sys.exit(1)

    url = f"{config['api_url']}/api/v2/logs/ingest"
    headers = {
        "Authorization": f"Api-Token {api_token}",
        "Content-Type": "application/json; charset=utf-8"
    }

    total = len(entries)
    sent = 0
    errors = 0
    batch_size = config["batch_size"]

    for i in range(0, total, batch_size):
        batch = entries[i:i + batch_size]
        dt_batch = [convert_to_dynatrace_format(e) for e in batch]
        try:
            resp = requests.post(url, json=dt_batch, headers=headers, verify=False, timeout=30)
            if resp.status_code in (200, 204):
                sent += len(batch)
                print(f"  Sent batch {i // batch_size + 1}: {len(batch)} entries (total: {sent}/{total})")
            else:
                errors += len(batch)
                print(f"  ERROR batch {i // batch_size + 1}: HTTP {resp.status_code} - {resp.text[:200]}")
        except requests.RequestException as e:
            errors += len(batch)
            print(f"  ERROR batch {i // batch_size + 1}: {e}")
        time.sleep(0.2)

    return sent, errors


# =============================================================================
#  Analysis (local, pre-ingestion)
# =============================================================================

def analyze_entries(all_entries):
    """Analyze parsed entries and return a summary dict."""
    stp_entries = [e for e in all_entries if e.get("is_stp_related")]
    total = len(all_entries)
    stp_count = len(stp_entries)

    # Switches discovered
    switches = {}
    for e in all_entries:
        ip = e.get("switch_ip", "unknown")
        if ip not in switches:
            switches[ip] = {
                "model": e.get("switch_model", ""),
                "hostname": e.get("switch_hostname", ""),
                "total": 0, "stp": 0
            }
        switches[ip]["total"] += 1
        if e.get("is_stp_related"):
            switches[ip]["stp"] += 1

    # STP event types
    stp_types = {}
    for e in stp_entries:
        t = e.get("stp_event_type", "UNKNOWN")
        stp_types[t] = stp_types.get(t, 0) + 1

    # VLANs (from all entries, not just STP)
    vlans = {}
    for e in all_entries:
        v = e.get("vlan_id")
        if v:
            vlans[v] = vlans.get(v, 0) + 1

    # Interfaces (from all entries)
    interfaces = {}
    for e in all_entries:
        iface = e.get("interface")
        if iface:
            interfaces[iface] = interfaces.get(iface, 0) + 1

    # MAC addresses (from all entries)
    macs = {}
    for e in all_entries:
        mac = e.get("mac_address")
        if mac:
            macs[mac] = macs.get(mac, 0) + 1

    # Root bridge changes
    root_changes = sum(1 for e in stp_entries if e.get("stp_event_type") == "STP_ROOT_BRIDGE_CHANGE")

    # Event categories breakdown
    categories = {}
    event_codes = {}
    for e in all_entries:
        cat = e.get("event_category", "other")
        code = e.get("event_code", "UNKNOWN")
        categories[cat] = categories.get(cat, 0) + 1
        event_codes[code] = event_codes.get(code, 0) + 1

    # Interface-specific stats
    iface_up = sum(1 for e in all_entries if e.get("event_code") in ("IFM_OSTATE_UP", "LINK_UP"))
    iface_down = sum(1 for e in all_entries if e.get("event_code") in ("IFM_OSTATE_DN", "LINK_DOWN"))
    iface_admin_up = sum(1 for e in all_entries if e.get("event_code") == "IFM_ASTATE_UP")
    iface_admin_down = sum(1 for e in all_entries if e.get("event_code") == "IFM_ASTATE_DN")

    # CPU/Performance
    cpu_high = sum(1 for e in all_entries if e.get("event_code") == "PM_SYS_UTIL_HI")
    cpu_low = sum(1 for e in all_entries if e.get("event_code") == "PM_SYS_UTIL_LO")

    # LACP
    lacp_grouped = sum(1 for e in all_entries if e.get("event_code") == "LACP_PORT_GROUPED")
    lacp_ungrouped = sum(1 for e in all_entries if e.get("event_code") == "LACP_PORT_UNGROUPED")

    # VLT
    vlt_peer_up = sum(1 for e in all_entries if e.get("event_code") == "VLT_PEER_UP")
    vlt_peer_down = sum(1 for e in all_entries if e.get("event_code") == "VLT_PEER_DOWN")
    vlt_channel_up = sum(1 for e in all_entries if e.get("event_code") == "VLT_PORT_CHANNEL_UP")
    vlt_channel_down = sum(1 for e in all_entries if e.get("event_code") == "VLT_PORT_CHANNEL_DOWN")

    # Hardware
    psu_faults = sum(1 for e in all_entries if e.get("event_code") == "EQM_MORE_PSU_FAULT")

    # System
    restarts = sum(1 for e in all_entries if e.get("event_code") in ("ALM_SYSTEM_RESTART", "NDM_SYSTEM_RELOAD"))
    disk_warnings = sum(1 for e in all_entries if e.get("event_code") == "SYS_STAT_LOW_DISK_SPACE")
    mac_moves = sum(1 for e in all_entries if e.get("event_code") == "FDB_MAC_MOVE")

    # Auth
    auth_events = categories.get("auth", 0)

    summary = {
        "total_logs": total,
        "stp_count": stp_count,
        "stp_pct": (stp_count / total * 100) if total > 0 else 0,
        "switches": switches,
        "stp_types": dict(sorted(stp_types.items(), key=lambda x: -x[1])),
        "top_vlans": dict(sorted(vlans.items(), key=lambda x: -x[1])[:15]),
        "top_interfaces": dict(sorted(interfaces.items(), key=lambda x: -x[1])[:15]),
        "top_macs": dict(sorted(macs.items(), key=lambda x: -x[1])[:10]),
        "root_bridge_changes": root_changes,
        "num_vlans_affected": len(vlans),
        # New: category breakdown
        "categories": dict(sorted(categories.items(), key=lambda x: -x[1])),
        "top_event_codes": dict(sorted(event_codes.items(), key=lambda x: -x[1])[:25]),
        # Interface
        "iface_up": iface_up, "iface_down": iface_down,
        "iface_admin_up": iface_admin_up, "iface_admin_down": iface_admin_down,
        # CPU
        "cpu_high": cpu_high, "cpu_low": cpu_low,
        # LACP
        "lacp_grouped": lacp_grouped, "lacp_ungrouped": lacp_ungrouped,
        # VLT
        "vlt_peer_up": vlt_peer_up, "vlt_peer_down": vlt_peer_down,
        "vlt_channel_up": vlt_channel_up, "vlt_channel_down": vlt_channel_down,
        # Hardware / System
        "psu_faults": psu_faults, "restarts": restarts,
        "disk_warnings": disk_warnings, "mac_moves": mac_moves,
        "auth_events": auth_events,
    }
    return summary


def print_summary(summary):
    print(f"\n{'=' * 70}")
    print("DELL SWITCH LOG ANALYSIS - COMPREHENSIVE")
    print(f"{'=' * 70}")
    print(f"Total logs: {summary['total_logs']:,}")
    print(f"STP events: {summary['stp_count']:,} ({summary['stp_pct']:.1f}%)")

    print("\n--- Discovered Switches ---")
    for ip, info in summary["switches"].items():
        print(f"  {ip} ({info['model']}, {info['hostname']}): {info['total']:,} total, {info['stp']:,} STP")

    print("\n--- Event Categories ---")
    for cat, cnt in summary["categories"].items():
        pct = cnt / summary["total_logs"] * 100 if summary["total_logs"] else 0
        print(f"  {cat}: {cnt:,} ({pct:.1f}%)")

    print("\n--- STP Event Types ---")
    for t, c in summary["stp_types"].items():
        print(f"  {t}: {c:,}")

    if summary["iface_up"] or summary["iface_down"]:
        print(f"\n--- Interface Health ---")
        print(f"  Link Up: {summary['iface_up']:,}  |  Link Down: {summary['iface_down']:,}")
        print(f"  Admin Up: {summary['iface_admin_up']:,}  |  Admin Down: {summary['iface_admin_down']:,}")

    if summary["cpu_high"]:
        print(f"\n--- CPU Utilization ---")
        print(f"  High alarms: {summary['cpu_high']:,}  |  Cleared: {summary['cpu_low']:,}")

    if summary["lacp_grouped"] or summary["lacp_ungrouped"]:
        print(f"\n--- LACP / Link Aggregation ---")
        print(f"  Grouped: {summary['lacp_grouped']:,}  |  Ungrouped: {summary['lacp_ungrouped']:,}")

    if summary["vlt_peer_up"] or summary["vlt_peer_down"]:
        print(f"\n--- VLT (Virtual Link Trunking) ---")
        print(f"  Peer Up: {summary['vlt_peer_up']:,}  |  Peer Down: {summary['vlt_peer_down']:,}")
        print(f"  Channel Up: {summary['vlt_channel_up']:,}  |  Channel Down: {summary['vlt_channel_down']:,}")

    if summary["psu_faults"] or summary["restarts"] or summary["disk_warnings"]:
        print(f"\n--- System / Hardware ---")
        if summary["psu_faults"]: print(f"  [ALERT] PSU Faults: {summary['psu_faults']:,}")
        if summary["restarts"]: print(f"  [ALERT] System Restarts: {summary['restarts']:,}")
        if summary["disk_warnings"]: print(f"  [WARN]  Low Disk Space Warnings: {summary['disk_warnings']:,}")

    if summary["mac_moves"]:
        print(f"  MAC Moves (potential loops): {summary['mac_moves']:,}")

    if summary["auth_events"]:
        print(f"\n--- Authentication ---")
        print(f"  Auth events: {summary['auth_events']:,}")

    if summary["top_vlans"]:
        print("\n--- Top Affected VLANs ---")
        for v, c in list(summary["top_vlans"].items())[:10]:
            print(f"  VLAN {v}: {c:,}")

    if summary["top_interfaces"]:
        print("\n--- Top Affected Interfaces ---")
        for iface, c in list(summary["top_interfaces"].items())[:10]:
            print(f"  {iface}: {c:,}")

    if summary["root_bridge_changes"] > 0:
        print(f"\n[CRITICAL] Root Bridge Changes: {summary['root_bridge_changes']:,}")
        print(f"  Affected VLANs: {summary['num_vlans_affected']}")

    print(f"{'=' * 70}")


def build_findings_markdown(summary):
    """Generate a dynamic Key Findings markdown section from analysis data."""
    lines = ["## Key Findings & Recommended Actions\n"]

    # Root bridge instability
    if summary.get("root_bridge_changes", 0) > 0:
        lines.append("### CRITICAL: STP Root Bridge Instability")
        lines.append(f"- **{summary['root_bridge_changes']:,} Root Bridge Change events** detected")
        stp_switches = sorted(summary["switches"].items(), key=lambda x: -x[1]["stp"])
        for ip, info in stp_switches[:3]:
            if info["stp"] > 0:
                lines.append(f"- {ip} ({info['hostname']}): **{info['stp']:,}** STP events")
        if summary.get("top_macs"):
            top_mac, top_mac_count = next(iter(summary["top_macs"].items()))
            lines.append(f"- **MAC {top_mac}** in {top_mac_count:,} events - likely competing root")
        lines.append(f"- **{summary['num_vlans_affected']}+ VLANs** affected across fabric")

    # Interface instability
    if summary.get("iface_down", 0) > 10:
        lines.append(f"\n### WARNING: Interface Instability")
        lines.append(f"- **{summary['iface_down']:,} link-down** events detected")
        lines.append(f"- {summary.get('iface_up', 0):,} link-up events (flapping indicator)")
        if summary.get("iface_admin_down", 0) > 0:
            lines.append(f"- {summary['iface_admin_down']:,} admin-down events")

    # CPU stress
    if summary.get("cpu_high", 0) > 0:
        lines.append(f"\n### WARNING: CPU High Utilization")
        lines.append(f"- **{summary['cpu_high']:,} high-utilization alarms** raised")
        lines.append(f"- {summary.get('cpu_low', 0):,} cleared — check if alarms are persistent")

    # VLT issues
    if summary.get("vlt_peer_down", 0) > 0:
        lines.append(f"\n### WARNING: VLT Peer Instability")
        lines.append(f"- **{summary['vlt_peer_down']:,} VLT peer-down** events")
        lines.append(f"- {summary.get('vlt_channel_down', 0):,} VLT port-channel down events")
        lines.append(f"- {summary.get('vlt_peer_up', 0):,} peer-up / {summary.get('vlt_channel_up', 0):,} channel-up recoveries")

    # LACP churn
    if summary.get("lacp_ungrouped", 0) > 10:
        lines.append(f"\n### WARNING: LACP Port Churn")
        lines.append(f"- **{summary['lacp_ungrouped']:,} port-ungrouped** events (ports leaving LAGs)")
        lines.append(f"- {summary.get('lacp_grouped', 0):,} port-grouped events")

    # Hardware
    if summary.get("psu_faults", 0) > 0:
        lines.append(f"\n### ALERT: Hardware Issues")
        lines.append(f"- **{summary['psu_faults']:,} PSU fault(s)** detected")

    # System
    if summary.get("restarts", 0) > 0:
        lines.append(f"\n### ALERT: System Restarts")
        lines.append(f"- **{summary['restarts']:,} system restart/reload** events")

    if summary.get("disk_warnings", 0) > 0:
        lines.append(f"\n### WARNING: Low Disk Space")
        lines.append(f"- **{summary['disk_warnings']:,}** low disk space warnings")

    if summary.get("mac_moves", 0) > 5:
        lines.append(f"\n### WARNING: MAC Address Flapping")
        lines.append(f"- **{summary['mac_moves']:,} MAC move** events — potential loops or misconfigs")

    # Recommendations
    lines.append("\n### Recommended Actions")
    if summary.get("root_bridge_changes", 0) > 0:
        lines.append("1. Verify STP root bridge priority on all switches")
        if summary.get("top_macs"):
            top_mac = next(iter(summary["top_macs"]))
            lines.append(f"2. Investigate MAC {top_mac} - identify the contesting device")
    if summary.get("iface_down", 0) > 10:
        lines.append("3. Check top flapping interfaces for cable/SFP issues")
    if summary.get("cpu_high", 0) > 0:
        lines.append("4. Review CPU utilization trends — consider control plane policing")
    if summary.get("vlt_peer_down", 0) > 0:
        lines.append("5. Review VLT heartbeat link and peer keepalive configuration")
    lines.append("- Enable BPDU Guard on access ports")
    if summary.get("top_interfaces"):
        top_iface = next(iter(summary["top_interfaces"]))
        lines.append(f"- Review interface {top_iface} ({summary['top_interfaces'][top_iface]:,} events)")

    return "\n".join(lines)


# =============================================================================
#  OAuth PKCE Flow (for Gen 3 Dashboard creation)
# =============================================================================

auth_result = {"code": None, "state": None, "error": None}
auth_event = threading.Event()


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/auth/login":
            params = urllib.parse.parse_qs(parsed.query)
            if "error" in params:
                auth_result["error"] = params["error"][0]
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>OAuth Error</h1>")
            elif "code" in params and "state" in params:
                auth_result["code"] = params["code"][0]
                auth_result["state"] = params["state"][0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<h1>Authorization Successful!</h1>"
                    b"<p>You can close this tab.</p>"
                    b"<script>setTimeout(()=>window.close(),2000)</script>"
                )
            else:
                self.send_response(400)
                self.end_headers()
            auth_event.set()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def discover_sso_url(env_url):
    auth_url = f"{env_url}/platform/oauth2/authorization/dynatrace-sso"
    try:
        resp = requests.head(auth_url, allow_redirects=False, timeout=10)
        if 300 <= resp.status_code < 400:
            location = resp.headers.get("Location", "")
            if location:
                parsed = urllib.parse.urlparse(location)
                return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass
    return "https://sso.dynatrace.com"


def perform_oauth_flow(config):
    """Interactive OAuth PKCE flow. Returns access_token or None."""
    global auth_result, auth_event
    auth_result = {"code": None, "state": None, "error": None}
    auth_event = threading.Event()

    env_url = config["env_url"]
    client_id = config["oauth_client_id"]
    port = config["redirect_port"]
    redirect_uri = f"http://localhost:{port}/auth/login"

    scopes = [
        "app-engine:apps:run",
        "storage:events:read", "storage:user.events:read", "storage:buckets:read",
        "storage:security.events:read", "storage:entities:read", "storage:smartscape:read",
        "storage:logs:read", "storage:metrics:read", "storage:bizevents:read",
        "storage:spans:read", "storage:system:read", "app-settings:objects:read",
        "document:documents:write", "document:documents:read",
    ]

    print("\n--- OAuth PKCE Authentication ---")
    sso_url = discover_sso_url(env_url)
    print(f"  SSO: {sso_url}")

    code_verifier = base64url_encode(secrets.token_bytes(46))
    code_challenge = base64url_encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
    state = secrets.token_urlsafe(32)

    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "response_type": "code",
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
        "scope": " ".join(scopes),
    }
    auth_url = f"{sso_url}/oauth2/authorize?{urllib.parse.urlencode(auth_params)}"

    server = HTTPServer(("localhost", port), OAuthCallbackHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print("  Opening browser for authentication...")
    webbrowser.open(auth_url)
    print("  Waiting for authorization (up to 5 minutes)...")
    auth_event.wait(timeout=300)
    server.shutdown()

    if auth_result["error"] or not auth_result["code"]:
        print(f"  OAuth failed: {auth_result.get('error', 'timeout')}")
        return None
    if auth_result["state"] != state:
        print("  State mismatch!")
        return None

    print("  Authorization received! Exchanging for token...")
    token_resp = requests.post(
        f"{sso_url}/sso/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": auth_result["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    if token_resp.status_code != 200:
        print(f"  Token exchange failed: {token_resp.status_code} - {token_resp.text[:200]}")
        return None

    token = token_resp.json().get("access_token")
    if token:
        print("  Access token obtained!")
    return token


# =============================================================================
#  Dashboard Creation
# =============================================================================

def _grail_query(url, headers, dql, max_records=10, max_wait=30):
    """Execute a Grail DQL query, handling async polling. Returns parsed records or []."""
    import time as _time
    payload = {"query": dql, "maxResultRecords": max_records, "fetchTimeoutSeconds": 60}
    resp = requests.post(url, json=payload, headers=headers, timeout=90)
    data = resp.json()
    print(f"    Initial: status={resp.status_code} keys={list(data.keys())}")

    # Poll if async (202)
    if resp.status_code == 202 and "requestToken" in data:
        token = data["requestToken"]
        deadline = _time.time() + max_wait
        attempt = 0
        while _time.time() < deadline:
            _time.sleep(3)
            attempt += 1
            poll_resp = requests.post(url, json={"query": dql, "requestToken": token, "fetchTimeoutSeconds": 60},
                                      headers=headers, timeout=90)
            data = poll_resp.json()
            state = data.get("state", "")
            if attempt <= 3 or attempt % 10 == 0:
                print(f"    Poll #{attempt}: state={state}")
            if state == "SUCCEEDED":
                break
            elif state == "RUNNING":
                token = data.get("requestToken", token)
                continue
            else:
                print(f"    Query ended: state={state} body={str(data)[:200]}")
                return []
        else:
            print(f"    Query timed out after {max_wait}s ({attempt} polls)")
            return []

    records = data.get("result", {}).get("records", [])
    if not records:
        records = data.get("records", [])
    print(f"    Records found: {len(records)}")
    return records


def query_ingestion_timeframe(config, access_token):
    """Query Grail to find the actual timeframe of ingested dell-switch logs."""
    url = f"{config['env_url']}/platform/storage/query/v1/query:execute"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    # Use two fast limit-1 queries instead of one slow summarize
    scan = "from:now()-7d"
    dql_earliest = f'fetch logs, {scan} | filter log.source == "dell-switch" | sort timestamp asc | limit 1 | fields timestamp'
    dql_latest = f'fetch logs, {scan} | filter log.source == "dell-switch" | sort timestamp desc | limit 1 | fields timestamp'
    dql_count = f'fetch logs, {scan} | filter log.source == "dell-switch" | summarize total=count()'

    try:
        print("  Querying earliest record...")
        earliest_recs = _grail_query(url, headers, dql_earliest, max_records=1)
        if not earliest_recs:
            print("  No dell-switch logs found.")
            return None, None, 0

        print("  Querying latest record...")
        latest_recs = _grail_query(url, headers, dql_latest, max_records=1)

        print("  Querying total count...")
        count_recs = _grail_query(url, headers, dql_count, max_records=1)

        earliest_ts = earliest_recs[0].get("timestamp", "")
        latest_ts = latest_recs[0].get("timestamp", "") if latest_recs else earliest_ts
        total = count_recs[0].get("total", 0) if count_recs else 0
        if isinstance(total, str):
            total = int(total)

        from datetime import timedelta
        e_parsed = datetime.fromisoformat(str(earliest_ts).replace("Z", "+00:00"))
        l_parsed = datetime.fromisoformat(str(latest_ts).replace("Z", "+00:00"))
        e_buffered = (e_parsed - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        l_buffered = (l_parsed + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"  Found {total} logs: {e_buffered} to {l_buffered}")
        return e_buffered, l_buffered, total
    except Exception as e:
        print(f"  Grail query failed: {e}")
    return None, None, 0


def build_dashboard(summary, time_from, time_to):
    """Build Gen 3 dashboard JSON with comprehensive analysis tiles."""
    tile_counter = [0]
    def tid():
        tile_counter[0] += 1
        return str(uuid.uuid4()).replace("-", "")[:12]

    # Timeframe clause for all queries
    tf = f', from:"{time_from}", to:"{time_to}"'
    src = 'log.source == "dell-switch"'

    # Dynamic header
    switch_list = ", ".join(
        f"{info['hostname'] or ip} ({info['model']})"
        for ip, info in summary.get("switches", {}).items()
    )
    cats = summary.get("categories", {})
    cat_summary = " | ".join(f"**{k.title()}:** {v:,}" for k, v in list(cats.items())[:6])
    header = (
        f"# Dell Switch Comprehensive Analysis Dashboard\n\n"
        f"**Switches:** {switch_list}\n\n"
        f"**Total Logs:** {summary['total_logs']:,} | "
        f"**STP Events:** {summary['stp_count']:,} ({summary['stp_pct']:.1f}%)\n\n"
        f"{cat_summary}"
    )

    findings = build_findings_markdown(summary)

    tiles = {}
    layout = []
    y = 0  # Track vertical position

    def add_tile(tile_def, w=24, h=6):
        nonlocal y
        t = tid()
        tiles[t] = tile_def
        layout.append({"w": w, "h": h, "x": 0 if w == 24 else layout[-1]["x"] + layout[-1]["w"] if layout and layout[-1]["y"] == y else 0, "y": y, "i": t})
        return t

    def add_row(tile_defs):
        """Add tiles in a row, each gets equal width (24 total)."""
        nonlocal y
        w = 24 // len(tile_defs)
        x = 0
        h = tile_defs[0].get("_h", 5)
        for td in tile_defs:
            th = td.pop("_h", h)
            t = tid()
            tiles[t] = td
            layout.append({"w": w, "h": th, "x": x, "y": y, "i": t})
            x += w
        y += h

    def data_tile(title, query, viz, h=6):
        return {
            "type": "data", "title": title,
            "query": query,
            "visualization": viz,
            "visualizationSettings": {"thresholds": []},
            "davis": {"enabled": False, "davisVisualization": {"isAvailable": True}}
        }

    # ===================== HEADER =====================
    t_hdr = tid()
    tiles[t_hdr] = {"type": "markdown", "title": "", "content": header}
    layout.append({"w": 24, "h": 3, "x": 0, "y": y, "i": t_hdr})
    y += 3

    # ===================== KPI ROW =====================
    add_row([
        {**data_tile("Total Logs",
            f'fetch logs{tf}\n| filter {src}\n| summarize `Total` = count()',
            "singleValue"), "_h": 4},
        {**data_tile("STP Events",
            f'fetch logs{tf}\n| filter {src}\n| filter stp.related == "true"\n| summarize `STP` = count()',
            "singleValue"), "_h": 4},
        {**data_tile("Interface Events",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "interface"\n| summarize `Interface` = count()',
            "singleValue"), "_h": 4},
        {**data_tile("Switches",
            f'fetch logs{tf}\n| filter {src}\n| summarize `Switches` = countDistinct(switch.ip)',
            "singleValue"), "_h": 4},
    ])

    # ===================== OVERVIEW SECTION =====================
    t_sec1 = tid()
    tiles[t_sec1] = {"type": "markdown", "title": "", "content": "## Overview"}
    layout.append({"w": 24, "h": 1, "x": 0, "y": y, "i": t_sec1})
    y += 1

    # Event categories + severity distribution
    t_cat = tid()
    tiles[t_cat] = data_tile("Events by Category",
        f'fetch logs{tf}\n| filter {src}\n| summarize `Events` = count(), by:{{`Category` = event.category}}\n| sort `Events`, direction:"descending"',
        "pieChart")
    layout.append({"w": 12, "h": 7, "x": 0, "y": y, "i": t_cat})

    t_sev = tid()
    tiles[t_sev] = data_tile("Events by Severity",
        f'fetch logs{tf}\n| filter {src}\n| summarize `Events` = count(), by:{{`Severity` = severity}}\n| sort `Events`, direction:"descending"',
        "categoricalBarChart")
    layout.append({"w": 12, "h": 7, "x": 12, "y": y, "i": t_sev})
    y += 7

    # Events by switch
    t_sw = tid()
    tiles[t_sw] = data_tile("Events by Switch & Category",
        f'fetch logs{tf}\n| filter {src}\n| summarize `Events` = count(), by:{{`Switch` = switch.ip, `Category` = event.category}}\n| sort `Events`, direction:"descending"',
        "table")
    layout.append({"w": 24, "h": 6, "x": 0, "y": y, "i": t_sw})
    y += 6

    # ===================== STP SECTION =====================
    if summary.get("stp_count", 0) > 0:
        t_sec2 = tid()
        tiles[t_sec2] = {"type": "markdown", "title": "", "content": "## STP (Spanning Tree Protocol) Analysis"}
        layout.append({"w": 24, "h": 1, "x": 0, "y": y, "i": t_sec2})
        y += 1

        t_stp_type = tid()
        tiles[t_stp_type] = data_tile("STP Events by Type",
            f'fetch logs{tf}\n| filter {src}\n| filter stp.related == "true"\n| summarize `Events` = count(), by:{{`STP Type` = stp.event.type}}\n| sort `Events`, direction:"descending"',
            "pieChart")
        layout.append({"w": 12, "h": 7, "x": 0, "y": y, "i": t_stp_type})

        t_stp_sw = tid()
        tiles[t_stp_sw] = data_tile("STP Events by Switch",
            f'fetch logs{tf}\n| filter {src}\n| filter stp.related == "true"\n| summarize `Events` = count(), by:{{`Switch` = switch.ip}}\n| sort `Events`, direction:"descending"',
            "categoricalBarChart")
        layout.append({"w": 12, "h": 7, "x": 12, "y": y, "i": t_stp_sw})
        y += 7

        t_stp_vlan = tid()
        tiles[t_stp_vlan] = data_tile("Top 15 Affected VLANs",
            f'fetch logs{tf}\n| filter {src}\n| filter stp.related == "true"\n| filter isNotNull(vlan.id)\n| summarize `Events` = count(), by:{{`VLAN` = vlan.id}}\n| sort `Events`, direction:"descending"\n| limit 15',
            "categoricalBarChart")
        layout.append({"w": 12, "h": 7, "x": 0, "y": y, "i": t_stp_vlan})

        t_stp_iface = tid()
        tiles[t_stp_iface] = data_tile("Top STP Interfaces",
            f'fetch logs{tf}\n| filter {src}\n| filter stp.related == "true"\n| filter isNotNull(interface.name)\n| summarize `Events` = count(), by:{{`Interface` = interface.name, `Switch` = switch.ip}}\n| sort `Events`, direction:"descending"\n| limit 15',
            "table")
        layout.append({"w": 12, "h": 7, "x": 12, "y": y, "i": t_stp_iface})
        y += 7

        t_stp_mac = tid()
        tiles[t_stp_mac] = data_tile("MAC Addresses in STP Events",
            f'fetch logs{tf}\n| filter {src}\n| filter stp.related == "true"\n| filter isNotNull(mac.address)\n| summarize `Events` = count(), by:{{`MAC` = mac.address}}\n| sort `Events`, direction:"descending"\n| limit 10',
            "table")
        layout.append({"w": 24, "h": 5, "x": 0, "y": y, "i": t_stp_mac})
        y += 5

    # ===================== INTERFACE SECTION =====================
    iface_total = summary.get("iface_up", 0) + summary.get("iface_down", 0) + summary.get("iface_admin_up", 0) + summary.get("iface_admin_down", 0)
    if iface_total > 0 or cats.get("interface", 0):
        t_sec3 = tid()
        tiles[t_sec3] = {"type": "markdown", "title": "", "content": "## Interface Health"}
        layout.append({"w": 24, "h": 1, "x": 0, "y": y, "i": t_sec3})
        y += 1

        t_if_code = tid()
        tiles[t_if_code] = data_tile("Interface Events by Type",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "interface"\n| summarize `Events` = count(), by:{{`Event` = event.code}}\n| sort `Events`, direction:"descending"',
            "categoricalBarChart")
        layout.append({"w": 12, "h": 7, "x": 0, "y": y, "i": t_if_code})

        t_if_top = tid()
        tiles[t_if_top] = data_tile("Top Interfaces by Event Count",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "interface"\n| filter isNotNull(interface.name)\n| summarize `Events` = count(), by:{{`Interface` = interface.name, `Switch` = switch.ip}}\n| sort `Events`, direction:"descending"\n| limit 15',
            "table")
        layout.append({"w": 12, "h": 7, "x": 12, "y": y, "i": t_if_top})
        y += 7

    # ===================== AUTH SECTION =====================
    if summary.get("auth_events", 0) > 0 or cats.get("auth", 0):
        t_sec4 = tid()
        tiles[t_sec4] = {"type": "markdown", "title": "", "content": "## Authentication & Access"}
        layout.append({"w": 24, "h": 1, "x": 0, "y": y, "i": t_sec4})
        y += 1

        t_auth = tid()
        tiles[t_auth] = data_tile("Auth Events by Switch",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "auth"\n| summarize `Events` = count(), by:{{`Switch` = switch.ip}}\n| sort `Events`, direction:"descending"',
            "categoricalBarChart")
        layout.append({"w": 12, "h": 6, "x": 0, "y": y, "i": t_auth})

        t_auth_log = tid()
        tiles[t_auth_log] = data_tile("Recent Auth Events",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "auth"\n| sort timestamp, direction:"descending"\n| limit 50\n| fields timestamp, switch.ip, event.code, content',
            "table")
        layout.append({"w": 12, "h": 6, "x": 12, "y": y, "i": t_auth_log})
        y += 6

    # ===================== CPU / PERFORMANCE SECTION =====================
    if summary.get("cpu_high", 0) > 0 or cats.get("performance", 0):
        t_sec5 = tid()
        tiles[t_sec5] = {"type": "markdown", "title": "", "content": "## CPU & Performance"}
        layout.append({"w": 24, "h": 1, "x": 0, "y": y, "i": t_sec5})
        y += 1

        t_cpu = tid()
        tiles[t_cpu] = data_tile("CPU Utilization Alarms",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "performance"\n| summarize `Events` = count(), by:{{`Alarm Type` = event.code}}\n| sort `Events`, direction:"descending"',
            "categoricalBarChart")
        layout.append({"w": 12, "h": 6, "x": 0, "y": y, "i": t_cpu})

        t_cpu_sw = tid()
        tiles[t_cpu_sw] = data_tile("CPU Alarms by Switch",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "performance"\n| summarize `Events` = count(), by:{{`Switch` = switch.ip, `Alarm` = event.code}}\n| sort `Events`, direction:"descending"',
            "table")
        layout.append({"w": 12, "h": 6, "x": 12, "y": y, "i": t_cpu_sw})
        y += 6

    # ===================== LACP SECTION =====================
    if summary.get("lacp_grouped", 0) + summary.get("lacp_ungrouped", 0) > 0 or cats.get("lacp", 0):
        t_sec6 = tid()
        tiles[t_sec6] = {"type": "markdown", "title": "", "content": "## LACP / Link Aggregation"}
        layout.append({"w": 24, "h": 1, "x": 0, "y": y, "i": t_sec6})
        y += 1

        t_lacp = tid()
        tiles[t_lacp] = data_tile("LACP Events",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "lacp"\n| summarize `Events` = count(), by:{{`Event` = event.code}}\n| sort `Events`, direction:"descending"',
            "categoricalBarChart")
        layout.append({"w": 12, "h": 6, "x": 0, "y": y, "i": t_lacp})

        t_lacp_det = tid()
        tiles[t_lacp_det] = data_tile("LACP Events by Interface",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "lacp"\n| filter isNotNull(interface.name)\n| summarize `Events` = count(), by:{{`Interface` = interface.name, `Event` = event.code, `Switch` = switch.ip}}\n| sort `Events`, direction:"descending"\n| limit 20',
            "table")
        layout.append({"w": 12, "h": 6, "x": 12, "y": y, "i": t_lacp_det})
        y += 6

    # ===================== VLT SECTION =====================
    if summary.get("vlt_peer_up", 0) + summary.get("vlt_peer_down", 0) > 0 or cats.get("vlt", 0):
        t_sec7 = tid()
        tiles[t_sec7] = {"type": "markdown", "title": "", "content": "## VLT (Virtual Link Trunking)"}
        layout.append({"w": 24, "h": 1, "x": 0, "y": y, "i": t_sec7})
        y += 1

        t_vlt = tid()
        tiles[t_vlt] = data_tile("VLT Events by Type",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "vlt"\n| summarize `Events` = count(), by:{{`Event` = event.code}}\n| sort `Events`, direction:"descending"',
            "categoricalBarChart")
        layout.append({"w": 12, "h": 6, "x": 0, "y": y, "i": t_vlt})

        t_vlt_det = tid()
        tiles[t_vlt_det] = data_tile("VLT Events by Switch",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "vlt"\n| summarize `Events` = count(), by:{{`Switch` = switch.ip, `Event` = event.code}}\n| sort `Events`, direction:"descending"',
            "table")
        layout.append({"w": 12, "h": 6, "x": 12, "y": y, "i": t_vlt_det})
        y += 6

    # ===================== HARDWARE SECTION =====================
    if summary.get("psu_faults", 0) > 0 or cats.get("hardware", 0):
        t_sec8 = tid()
        tiles[t_sec8] = {"type": "markdown", "title": "", "content": "## Hardware Health"}
        layout.append({"w": 24, "h": 1, "x": 0, "y": y, "i": t_sec8})
        y += 1

        t_hw = tid()
        tiles[t_hw] = data_tile("Hardware Events",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "hardware"\n| summarize `Events` = count(), by:{{`Event` = event.code}}\n| sort `Events`, direction:"descending"',
            "categoricalBarChart")
        layout.append({"w": 12, "h": 6, "x": 0, "y": y, "i": t_hw})

        t_hw_det = tid()
        tiles[t_hw_det] = data_tile("Hardware Events by Switch",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "hardware"\n| summarize `Events` = count(), by:{{`Switch` = switch.ip, `Event` = event.code}}\n| sort `Events`, direction:"descending"',
            "table")
        layout.append({"w": 12, "h": 6, "x": 12, "y": y, "i": t_hw_det})
        y += 6

    # ===================== SYSTEM SECTION =====================
    sys_events = summary.get("restarts", 0) + summary.get("disk_warnings", 0) + summary.get("mac_moves", 0)
    if sys_events > 0 or cats.get("system", 0):
        t_sec9 = tid()
        tiles[t_sec9] = {"type": "markdown", "title": "", "content": "## System & Other Events"}
        layout.append({"w": 24, "h": 1, "x": 0, "y": y, "i": t_sec9})
        y += 1

        t_sys = tid()
        tiles[t_sys] = data_tile("System Events by Type",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "system"\n| summarize `Events` = count(), by:{{`Event` = event.code}}\n| sort `Events`, direction:"descending"',
            "categoricalBarChart")
        layout.append({"w": 12, "h": 6, "x": 0, "y": y, "i": t_sys})

        t_sys_log = tid()
        tiles[t_sys_log] = data_tile("Recent System Events",
            f'fetch logs{tf}\n| filter {src}\n| filter event.category == "system"\n| sort timestamp, direction:"descending"\n| limit 50\n| fields timestamp, switch.ip, event.code, content',
            "table")
        layout.append({"w": 12, "h": 6, "x": 12, "y": y, "i": t_sys_log})
        y += 6

    # ===================== FINDINGS =====================
    t_find = tid()
    tiles[t_find] = {"type": "markdown", "title": "", "content": findings}
    layout.append({"w": 24, "h": 12, "x": 0, "y": y, "i": t_find})
    y += 12

    # ===================== ALL LOGS TABLE =====================
    t_all = tid()
    tiles[t_all] = data_tile("All Log Entries",
        f'fetch logs{tf}\n| filter {src}\n| sort timestamp, direction:"descending"\n| fields timestamp, switch.ip, severity, event.category, event.code, interface.name, vlan.id, content\n| limit 500',
        "table")
    layout.append({"w": 24, "h": 8, "x": 0, "y": y, "i": t_all})

    return {
        "version": 19,
        "variables": [],
        "settings": {},
        "importedWithCode": False,
        "tiles": tiles,
        "layouts": {"sm": layout}
    }


def create_dashboard(config, access_token, summary, time_from, time_to):
    """Create the Gen 3 dashboard via Document API."""
    content = build_dashboard(summary, time_from, time_to)
    content_str = json.dumps(content, ensure_ascii=True)

    doc_url = f"{config['env_url']}/platform/document/v1/documents"
    mp_headers = {"Authorization": f"Bearer {access_token}"}
    files = {"content": ("dashboard.json", content_str, "application/json")}
    data = {"name": "Dell Switch Comprehensive Analysis", "type": "dashboard", "isPrivate": "true"}

    print("\nCreating Gen 3 Dashboard...")
    resp = requests.post(doc_url, headers=mp_headers, files=files, data=data, timeout=30)

    if resp.status_code in (200, 201):
        doc_id = resp.json().get("id", "unknown")
        print(f"\n{'=' * 60}")
        print(f"  Dashboard created successfully!")
        print(f"  ID: {doc_id}")
        print(f"  URL: {config['env_url']}/ui/apps/dynatrace.dashboards/dashboard/{doc_id}")
        print(f"{'=' * 60}")
        return doc_id
    else:
        print(f"  Failed: {resp.status_code} - {resp.text[:300]}")
        return None


# =============================================================================
#  Main CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Dell Switch Log Analyzer for Dynatrace",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  DT_ENV_URL           Dynatrace environment URL (required)
  DT_API_TOKEN         API token with logs.ingest scope (required for ingestion)
  DT_OAUTH_CLIENT_ID   OAuth client ID (default: dt0s12.local-dt-mcp-server)
  DT_OAUTH_PORT        OAuth callback port (default: 5344)
  DT_BATCH_SIZE        Log ingestion batch size (default: 1000)

Examples:
  py dell_switch_log_analyzer.py ingest ./logs/
  py dell_switch_log_analyzer.py ingest switches.zip
  py dell_switch_log_analyzer.py dashboard
  py dell_switch_log_analyzer.py all ./logs/
        """
    )
    parser.add_argument("action", choices=["ingest", "dashboard", "all"],
                        help="ingest=parse & send logs, dashboard=create dashboard, all=both")
    parser.add_argument("path", nargs="?", default=".",
                        help="Path to log files (directory or .zip). Default: current dir")

    args = parser.parse_args()
    config = get_config()

    print(f"{'=' * 60}")
    print(f"  Dell Switch Log Analyzer for Dynatrace")
    print(f"  Environment: {config['env_url']}")
    print(f"{'=' * 60}")

    summary = None

    # --- INGEST ---
    if args.action in ("ingest", "all"):
        log_files = get_log_files(args.path)
        if not log_files:
            print("No log files found!")
            sys.exit(1)

        print(f"\nFound {len(log_files)} log file(s):")
        all_entries = []
        for f in log_files:
            print(f"  Parsing {f.name} ({f.stat().st_size:,} bytes)...")
            entries = parse_log_file(f)
            print(f"    -> {len(entries)} entries ({sum(1 for e in entries if e.get('is_stp_related'))} STP)")
            all_entries.extend(entries)

        print(f"\nTotal: {len(all_entries):,} entries")
        summary = analyze_entries(all_entries)
        print_summary(summary)

        # Save summary for dashboard use later
        summary_file = Path(args.path).parent / "analysis_summary.json"
        if Path(args.path).is_dir():
            summary_file = Path(args.path) / "analysis_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"\nSummary saved to: {summary_file}")

        # Ingest
        print(f"\nIngesting {len(all_entries):,} entries into Dynatrace...")
        print(f"  API: {config['api_url']}")
        ingest_start = datetime.now(timezone.utc)
        sent, errors = ingest_to_dynatrace(all_entries, config)
        ingest_end = datetime.now(timezone.utc)
        print(f"\nIngestion complete: {sent:,} sent, {errors:,} errors")

        if errors > 0:
            print("WARNING: Some entries failed to ingest. Check errors above.")

        # Record ingestion timeframe for dashboard use
        from datetime import timedelta
        ingestion_time_from = (ingest_start - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ingestion_time_to = (ingest_end + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Wait for Grail indexing
        print("\nWaiting 10 seconds for Grail indexing...")
        time.sleep(10)

    # --- DASHBOARD ---
    if args.action in ("dashboard", "all"):
        # Get OAuth token for Document API
        access_token = perform_oauth_flow(config)
        if not access_token:
            print("OAuth failed. Cannot create dashboard.")
            sys.exit(1)

        # Determine timeframe
        time_from = time_to = None
        total = 0
        if args.action == "all" and 'ingestion_time_from' in dir():
            # Use recorded ingestion time (faster, no Grail query needed)
            time_from = ingestion_time_from
            time_to = ingestion_time_to
            total = sent
            print(f"\n  Using ingestion timeframe: {time_from} to {time_to}")
        else:
            # Try Grail query with a 30s timeout (fast fail)
            print("\nQuerying ingestion timeframe from Grail...")
            time_from, time_to, total = query_ingestion_timeframe(config, access_token)

        # Fallback: if Grail didn't return data, use a broad default range
        if not time_from:
            print("  Grail query did not return data. Using default 7-day range.")
            from datetime import timedelta
            time_from = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
            time_to = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Load or generate summary
        if summary is None:
            # Try loading saved summary
            for candidate in [Path(".") / "analysis_summary.json",
                              Path(args.path) / "analysis_summary.json"]:
                if candidate.exists():
                    with open(candidate) as f:
                        summary = json.load(f)
                    print(f"  Loaded summary from {candidate}")
                    break

        if summary is None:
            # Try parsing local log files for summary
            print("  No saved summary. Parsing local log files...")
            try:
                log_files = get_log_files(args.path)
                if log_files:
                    all_entries = []
                    for lf in log_files:
                        entries = parse_log_file(lf)
                        all_entries.extend(entries)
                    if all_entries:
                        summary = analyze_entries(all_entries)
                        print(f"  Parsed {len(all_entries):,} entries from {len(log_files)} files")
            except Exception as e:
                print(f"  Could not parse local logs: {e}")

        if summary is None:
            # Minimal fallback summary
            print("  Using minimal summary (no local data available).")
            summary = {
                "total_logs": total or 0,
                "stp_count": 0, "stp_pct": 0,
                "switches": {}, "stp_types": {},
                "top_vlans": {}, "top_interfaces": {}, "top_macs": {},
                "root_bridge_changes": 0, "num_vlans_affected": 0,
                "categories": {}, "top_event_codes": {},
                "iface_up": 0, "iface_down": 0,
                "iface_admin_up": 0, "iface_admin_down": 0,
                "cpu_high": 0, "cpu_low": 0,
                "lacp_grouped": 0, "lacp_ungrouped": 0,
                "vlt_peer_up": 0, "vlt_peer_down": 0,
                "vlt_channel_up": 0, "vlt_channel_down": 0,
                "psu_faults": 0, "restarts": 0,
                "disk_warnings": 0, "mac_moves": 0, "auth_events": 0,
            }

        create_dashboard(config, access_token, summary, time_from, time_to)


if __name__ == "__main__":
    main()
