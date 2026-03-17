#!/usr/bin/env python3
"""
Dell Switch Log Analyzer for Dynatrace
=======================================
Generic tool to ingest Dell switch syslog files into Dynatrace and
auto-generate a Gen 3 STP analysis dashboard.

Supports:
  - Dell N-Series (N3048ET, N3048ET-ON, etc.) - BSD syslog format
  - Dell OS10 (S4128T-ON, S5248F-ON, etc.) - RFC5424 syslog format
  - Auto-discovers switch IPs, hostnames, and models from log content
  - Auto-detects ingestion timeframe for dashboard queries

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

                        is_stp = bool(STP_KEYWORDS.search(entry["message"]))
                        entry["is_stp_related"] = is_stp
                        if is_stp:
                            entry["stp_event_type"] = classify_stp_event(entry["message"])
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
                is_stp = bool(STP_KEYWORDS.search(entry["message"]))
                entry["is_stp_related"] = is_stp
                if is_stp:
                    entry["stp_event_type"] = classify_stp_event(entry["message"])
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
        dt_entry["stp.vlan.id"] = entry["vlan_id"]
    if entry.get("interface"):
        dt_entry["stp.interface"] = entry["interface"]
    if entry.get("mac_address"):
        dt_entry["stp.mac.address"] = entry["mac_address"]

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

    # VLANs
    vlans = {}
    for e in stp_entries:
        v = e.get("vlan_id")
        if v:
            vlans[v] = vlans.get(v, 0) + 1

    # Interfaces
    interfaces = {}
    for e in stp_entries:
        iface = e.get("interface")
        if iface:
            interfaces[iface] = interfaces.get(iface, 0) + 1

    # MAC addresses
    macs = {}
    for e in stp_entries:
        mac = e.get("mac_address")
        if mac:
            macs[mac] = macs.get(mac, 0) + 1

    # Root bridge changes
    root_changes = sum(1 for e in stp_entries if e.get("stp_event_type") == "STP_ROOT_BRIDGE_CHANGE")

    summary = {
        "total_logs": total,
        "stp_count": stp_count,
        "stp_pct": (stp_count / total * 100) if total > 0 else 0,
        "switches": switches,
        "stp_types": dict(sorted(stp_types.items(), key=lambda x: -x[1])),
        "top_vlans": dict(sorted(vlans.items(), key=lambda x: -x[1])[:15]),
        "top_interfaces": dict(sorted(interfaces.items(), key=lambda x: -x[1])[:10]),
        "top_macs": dict(sorted(macs.items(), key=lambda x: -x[1])[:10]),
        "root_bridge_changes": root_changes,
        "num_vlans_affected": len(vlans),
    }
    return summary


def print_summary(summary):
    print(f"\n{'=' * 70}")
    print("DELL SWITCH LOG ANALYSIS - STP FOCUS")
    print(f"{'=' * 70}")
    print(f"Total logs: {summary['total_logs']:,}")
    print(f"STP events: {summary['stp_count']:,} ({summary['stp_pct']:.1f}%)")

    print("\n--- Discovered Switches ---")
    for ip, info in summary["switches"].items():
        print(f"  {ip} ({info['model']}, {info['hostname']}): {info['total']:,} total, {info['stp']:,} STP")

    print("\n--- STP Event Types ---")
    for t, c in summary["stp_types"].items():
        print(f"  {t}: {c:,}")

    if summary["top_vlans"]:
        print("\n--- Top Affected VLANs ---")
        for v, c in summary["top_vlans"].items():
            print(f"  VLAN {v}: {c:,}")

    if summary["top_interfaces"]:
        print("\n--- Top Affected Interfaces ---")
        for iface, c in summary["top_interfaces"].items():
            print(f"  {iface}: {c:,}")

    if summary["top_macs"]:
        print("\n--- Top MAC Addresses ---")
        for mac, c in summary["top_macs"].items():
            print(f"  {mac}: {c:,}")

    if summary["root_bridge_changes"] > 0:
        print(f"\n[CRITICAL] Root Bridge Changes: {summary['root_bridge_changes']:,}")
        print(f"  Affected VLANs: {summary['num_vlans_affected']}")

    print(f"{'=' * 70}")


def build_findings_markdown(summary):
    """Generate a dynamic Key Findings markdown section from analysis data."""
    lines = ["## Key Findings & Recommended Actions\n"]

    # Root bridge instability
    if summary["root_bridge_changes"] > 0:
        lines.append("### CRITICAL: STP Root Bridge Instability")
        lines.append(f"- **{summary['root_bridge_changes']:,} Root Bridge Change events** detected")

        # Top switches with STP events
        stp_switches = sorted(summary["switches"].items(), key=lambda x: -x[1]["stp"])
        for ip, info in stp_switches[:3]:
            if info["stp"] > 0:
                lines.append(f"- {ip} ({info['hostname']}): **{info['stp']:,}** STP events")

        # Top MAC address
        if summary["top_macs"]:
            top_mac, top_mac_count = next(iter(summary["top_macs"].items()))
            lines.append(f"- **MAC {top_mac}** in {top_mac_count:,} events - likely competing root")

        lines.append(f"- **{summary['num_vlans_affected']}+ VLANs** affected across fabric")

    # Top STP event type
    if summary["stp_types"]:
        lines.append(f"\n### STP Event Breakdown")
        for t, c in list(summary["stp_types"].items())[:5]:
            lines.append(f"- {t}: **{c:,}** events")

    # Recommendations
    lines.append("\n### Recommended Actions")
    lines.append("1. Verify STP root bridge priority on all switches")
    if summary["top_macs"]:
        top_mac = next(iter(summary["top_macs"]))
        lines.append(f"2. Investigate MAC {top_mac} - identify the contesting device")
    lines.append("3. Enable BPDU Guard on access ports")
    if summary["top_interfaces"]:
        top_iface = next(iter(summary["top_interfaces"]))
        lines.append(f"4. Review interface {top_iface} ({summary['top_interfaces'][top_iface]:,} events)")
    lines.append("5. Check port-channels for STP consistency")

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
    """Build Gen 3 dashboard JSON with dynamic content."""
    def tid():
        return str(uuid.uuid4()).replace("-", "")[:12]

    t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11 = [tid() for _ in range(11)]

    # Timeframe clause for all queries
    tf = f', from:"{time_from}", to:"{time_to}"'

    # Dynamic header
    switch_list = ", ".join(
        f"{info['hostname'] or ip} ({info['model']})"
        for ip, info in summary["switches"].items()
    )
    header = (
        f"# Dell Switch STP Analysis Dashboard\n\n"
        f"**Switches:** {switch_list} | "
        f"**Total Logs:** {summary['total_logs']:,} | "
        f"**STP Events:** {summary['stp_count']:,} ({summary['stp_pct']:.1f}%)"
    )

    # Dynamic findings
    findings = build_findings_markdown(summary)

    return {
        "version": 19,
        "variables": [],
        "settings": {},
        "importedWithCode": False,
        "tiles": {
            t1: {
                "type": "markdown",
                "title": "",
                "content": header
            },
            t2: {
                "type": "data",
                "title": "Total STP Events",
                "query": f"fetch logs{tf}\n| filter matchesPhrase(log.source, \"dell-switch\")\n| filter stp.related == \"true\"\n| summarize `STP Events` = count()",
                "visualization": "singleValue",
                "visualizationSettings": {"thresholds": []},
                "davis": {"enabled": False, "davisVisualization": {"isAvailable": True}}
            },
            t3: {
                "type": "data",
                "title": "Total Logs Ingested",
                "query": f"fetch logs{tf}\n| filter matchesPhrase(log.source, \"dell-switch\")\n| summarize `Total Logs` = count()",
                "visualization": "singleValue",
                "visualizationSettings": {"thresholds": []},
                "davis": {"enabled": False, "davisVisualization": {"isAvailable": True}}
            },
            t4: {
                "type": "data",
                "title": "Switches Reporting STP",
                "query": f"fetch logs{tf}\n| filter matchesPhrase(log.source, \"dell-switch\")\n| filter stp.related == \"true\"\n| summarize `Switches` = countDistinct(switch.ip)",
                "visualization": "singleValue",
                "visualizationSettings": {"thresholds": []},
                "davis": {"enabled": False, "davisVisualization": {"isAvailable": True}}
            },
            t5: {
                "type": "data",
                "title": "STP Events by Type",
                "query": f"fetch logs{tf}\n| filter matchesPhrase(log.source, \"dell-switch\")\n| filter stp.related == \"true\"\n| summarize `Events` = count(), by:{{`STP Event Type` = stp.event.type}}\n| sort `Events`, direction:\"descending\"",
                "visualization": "pieChart",
                "visualizationSettings": {"thresholds": []},
                "davis": {"enabled": False, "davisVisualization": {"isAvailable": True}}
            },
            t6: {
                "type": "data",
                "title": "STP Events by Switch",
                "query": f"fetch logs{tf}\n| filter matchesPhrase(log.source, \"dell-switch\")\n| filter stp.related == \"true\"\n| summarize `Events` = count(), by:{{`Switch` = switch.ip}}\n| sort `Events`, direction:\"descending\"",
                "visualization": "categoricalBarChart",
                "visualizationSettings": {"thresholds": []},
                "davis": {"enabled": False, "davisVisualization": {"isAvailable": True}}
            },
            t7: {
                "type": "data",
                "title": "STP Events by Switch & Event Type",
                "query": f"fetch logs{tf}\n| filter matchesPhrase(log.source, \"dell-switch\")\n| filter stp.related == \"true\"\n| summarize `Events` = count(), by:{{`Switch IP` = switch.ip, `Switch Model` = switch.model, `STP Event Type` = stp.event.type}}\n| sort `Events`, direction:\"descending\"",
                "visualization": "table",
                "visualizationSettings": {"thresholds": []},
                "davis": {"enabled": False, "davisVisualization": {"isAvailable": True}}
            },
            t8: {
                "type": "data",
                "title": "Top 15 Affected VLANs",
                "query": f"fetch logs{tf}\n| filter matchesPhrase(log.source, \"dell-switch\")\n| filter stp.related == \"true\"\n| filter isNotNull(stp.vlan.id)\n| summarize `Events` = count(), by:{{`VLAN ID` = stp.vlan.id}}\n| sort `Events`, direction:\"descending\"\n| limit 15",
                "visualization": "categoricalBarChart",
                "visualizationSettings": {"thresholds": []},
                "davis": {"enabled": False, "davisVisualization": {"isAvailable": True}}
            },
            t9: {
                "type": "data",
                "title": "Top Affected Interfaces",
                "query": f"fetch logs{tf}\n| filter matchesPhrase(log.source, \"dell-switch\")\n| filter stp.related == \"true\"\n| filter isNotNull(stp.interface)\n| summarize `Events` = count(), by:{{`Interface` = stp.interface, `Switch` = switch.ip}}\n| sort `Events`, direction:\"descending\"\n| limit 15",
                "visualization": "table",
                "visualizationSettings": {"thresholds": []},
                "davis": {"enabled": False, "davisVisualization": {"isAvailable": True}}
            },
            t10: {
                "type": "data",
                "title": "MAC Addresses in STP Events",
                "query": f"fetch logs{tf}\n| filter matchesPhrase(log.source, \"dell-switch\")\n| filter stp.related == \"true\"\n| filter isNotNull(stp.mac.address)\n| summarize `Events` = count(), by:{{`MAC Address` = stp.mac.address}}\n| sort `Events`, direction:\"descending\"\n| limit 10",
                "visualization": "table",
                "visualizationSettings": {"thresholds": []},
                "davis": {"enabled": False, "davisVisualization": {"isAvailable": True}}
            },
            t11: {
                "type": "markdown",
                "title": "",
                "content": findings
            }
        },
        "layouts": {
            "sm": [
                {"w": 24, "h": 2, "x": 0, "y": 0, "i": t1},
                {"w": 8, "h": 4, "x": 0, "y": 2, "i": t2},
                {"w": 8, "h": 4, "x": 8, "y": 2, "i": t3},
                {"w": 8, "h": 4, "x": 16, "y": 2, "i": t4},
                {"w": 12, "h": 8, "x": 0, "y": 6, "i": t5},
                {"w": 12, "h": 8, "x": 12, "y": 6, "i": t6},
                {"w": 24, "h": 7, "x": 0, "y": 14, "i": t7},
                {"w": 14, "h": 8, "x": 0, "y": 21, "i": t8},
                {"w": 10, "h": 8, "x": 14, "y": 21, "i": t9},
                {"w": 24, "h": 6, "x": 0, "y": 29, "i": t10},
                {"w": 24, "h": 10, "x": 0, "y": 35, "i": t11}
            ]
        }
    }


def create_dashboard(config, access_token, summary, time_from, time_to):
    """Create the Gen 3 dashboard via Document API."""
    content = build_dashboard(summary, time_from, time_to)
    content_str = json.dumps(content, ensure_ascii=True)

    doc_url = f"{config['env_url']}/platform/document/v1/documents"
    mp_headers = {"Authorization": f"Bearer {access_token}"}
    files = {"content": ("dashboard.json", content_str, "application/json")}
    data = {"name": "Dell Switch STP Analysis", "type": "dashboard", "isPrivate": "true"}

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
            }

        create_dashboard(config, access_token, summary, time_from, time_to)


if __name__ == "__main__":
    main()
