# Dell Switch Log Analyzer for Dynatrace

A CLI tool that parses Dell switch syslog files, ingests them into Dynatrace Grail, performs comprehensive analysis, and auto-generates a Gen 3 dashboard — all in a single command.

## What It Does

1. **Parses** Dell switch syslog files (BSD and RFC5424 formats)
2. **Classifies** every event into categories: STP, Interface, Auth, CPU, LACP, VLT, Hardware, System
3. **Ingests** parsed log entries into Dynatrace via the Log Ingest API
4. **Analyzes** across all categories with key findings and recommendations
5. **Creates** a Dynatrace Gen 3 dashboard with 30+ interactive tiles

## Supported Switch Models

| Series | Models | Syslog Format |
|--------|--------|---------------|
| Dell N-Series | N3048ET, N3048ET-ON, etc. | BSD syslog |
| Dell OS10 | S4128T-ON, S5248F-ON, etc. | RFC5424 syslog |

The tool auto-detects the log format, switch IPs, hostnames, and models from the log content — no manual mapping required.

## Prerequisites

- **Python 3.8+**
- **`requests`** library: `pip install requests`
- **Dynatrace environment** with:
  - An **API token** with `logs.ingest` scope (for log ingestion)
  - An **OAuth client** configured for PKCE flow (for dashboard creation via Document API)

## Setup

### 1. Install dependency

```bash
pip install requests
```

### 2. Set environment variables

```powershell
# Required
$env:DT_ENV_URL = "https://abc12345.apps.dynatrace.com"    # Your Dynatrace environment URL
$env:DT_API_TOKEN = "dt0c01.XXXX.YYYY"                     # API token with logs.ingest scope

# Optional
$env:DT_OAUTH_CLIENT_ID = "dt0s12.local-dt-mcp-server"     # OAuth client ID (default shown)
$env:DT_OAUTH_PORT = "5344"                                 # OAuth callback port (default: 5344)
$env:DT_BATCH_SIZE = "1000"                                 # Log batch size (default: 1000)
```

On Linux/macOS:
```bash
export DT_ENV_URL="https://abc12345.apps.dynatrace.com"
export DT_API_TOKEN="dt0c01.XXXX.YYYY"
```

## Usage

### Full pipeline (recommended)

Parse logs, ingest into Dynatrace, and create a dashboard in one go:

```bash
python dell_switch_log_analyzer.py all ./my-switch-logs/
```

### Ingest only

Parse and send logs to Dynatrace without creating a dashboard:

```bash
python dell_switch_log_analyzer.py ingest ./my-switch-logs/
```

### Dashboard only

Create a dashboard from previously ingested data:

```bash
python dell_switch_log_analyzer.py dashboard ./my-switch-logs/
```

### ZIP file input

You can point directly to a ZIP file containing log files:

```bash
python dell_switch_log_analyzer.py all ./switch-logs.zip
```

## Log File Naming

The tool extracts switch IP addresses from filenames. Name your files with the switch IP, for example:

```
10.150.1.4_SH_logging.txt
10.150.1.7_Switch_Logs.txt
192.168.1.100_show_log.log
```

Any `.txt` or `.log` file in the directory will be processed. The IP is extracted from the filename automatically. If no IP is found, the filename is used as the switch identifier.

## What Gets Ingested

Each log entry is sent to Dynatrace with these attributes:

| Attribute | Description |
|-----------|-------------|
| `log.source` | `dell-switch` |
| `switch.ip` | Switch IP (from filename) |
| `switch.hostname` | Switch hostname (from log content) |
| `switch.model` | Detected model (N3048ET, S4128T-ON, etc.) |
| `severity` | Syslog severity level |
| `event.category` | Event category: `stp`, `interface`, `auth`, `performance`, `lacp`, `vlt`, `hardware`, `system` |
| `event.code` | Specific event code (e.g. `STP_ROOT_CHANGE`, `IFM_OSTATE_DN`, `PM_SYS_UTIL_HI`) |
| `stp.related` | `true` / `false` |
| `stp.event.type` | STP event classification (if STP-related) |
| `vlan.id` | VLAN ID (if present) |
| `interface.name` | Interface name (if present) |
| `mac.address` | MAC address (if present) |
| `dell.event.type` | OS10 application name |

## Event Categories

| Category | Events Detected |
|----------|----------------|
| **STP** | Root bridge changes, topology changes, port state transitions, BPDU, compatibility mode |
| **Interface** | Link up/down, admin state changes, interface flapping |
| **Auth** | User logins, session starts, password changes |
| **Performance** | CPU high/low utilization alarms, process utilization |
| **LACP** | Port grouped/ungrouped, LAG membership changes |
| **VLT** | Peer up/down, port-channel state, role elections, delay restore |
| **Hardware** | Fan tray, PSU detection/faults, unit detection, SFP changes |
| **System** | Restarts, reloads, low disk space, MAC moves, SupportAssist, mode changes |

## Dashboard

The generated Gen 3 dashboard has 30+ tiles organized into sections:

### Overview
- **KPI Row** — Total Logs, STP Events, Interface Events, Switch Count
- **Events by Category** — pie chart breakdown
- **Events by Severity** — bar chart
- **Events by Switch & Category** — detail table

### STP Analysis
- STP Events by Type (pie chart)
- STP Events by Switch (bar chart)
- Top 15 Affected VLANs
- Top STP Interfaces
- MAC Addresses in STP Events

### Interface Health
- Interface Events by Type (up/down/admin)
- Top Interfaces by Event Count

### Authentication & Access
- Auth Events by Switch
- Recent Auth Events log

### CPU & Performance
- CPU Utilization Alarms (high vs cleared)
- CPU Alarms by Switch

### LACP / Link Aggregation
- LACP Events (grouped vs ungrouped)
- LACP Events by Interface

### VLT (Virtual Link Trunking)
- VLT Events by Type
- VLT Events by Switch

### Hardware Health
- Hardware Events (fan, PSU, unit, SFP)
- Hardware Events by Switch

### System Events
- System Events by Type (restarts, disk, MAC moves)
- Recent System Events

### Key Findings
- Dynamic markdown with CRITICAL/WARNING findings and recommended actions

### All Logs
- Full searchable log table (500 most recent)

> **Note**: Sections only appear if relevant events exist in the data. The dashboard uses absolute timestamps matching the ingestion time window.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  Dell Switch     │     │  Log Parser      │     │  Dynatrace          │
│  Syslog Files    │────▶│  (BSD / RFC5424) │────▶│  Log Ingest API     │
│  (.txt / .log)   │     │  + Classifier    │     │  (Grail Storage)    │
└─────────────────┘     └──────────────────┘     └─────────┬───────────┘
                              │                            │
                              │ 8 Event Categories:       │
                              │ STP, Interface, Auth,     │
                              │ CPU, LACP, VLT,           │
                              │ Hardware, System           │
                              │                            │
                         ┌────▼─────────────┐              │
                         │  OAuth PKCE Flow │◀─────────────┘
                         │  (Browser Auth)  │
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │  Document API    │
                         │  Gen 3 Dashboard │
                         │  (30+ tiles)     │
                         └──────────────────┘
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `DT_ENV_URL not set` | Set the environment variable to your Dynatrace URL |
| `DT_API_TOKEN not set` | Create an API token with `logs.ingest` scope in Dynatrace |
| OAuth browser doesn't open | Manually visit the URL printed in the terminal |
| Dashboard tiles show no data | Data may not be indexed yet — wait a minute and refresh |
| `requests` not found | Run `pip install requests` |

## License

MIT
