# Dell Switch Log Analyzer for Dynatrace

A CLI tool that parses Dell switch syslog files, ingests them into Dynatrace Grail, analyzes STP (Spanning Tree Protocol) issues, and auto-generates a Gen 3 dashboard — all in a single command.

## What It Does

1. **Parses** Dell switch syslog files (BSD and RFC5424 formats)
2. **Ingests** parsed log entries into Dynatrace via the Log Ingest API
3. **Analyzes** STP-related events: root bridge changes, topology changes, BPDU events, port state transitions
4. **Creates** a Dynatrace Gen 3 dashboard with interactive charts and findings

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
| `syslog.severity` | Syslog severity level |
| `syslog.facility` | Syslog facility name |
| `dell.event.type` | Application/process that generated the log |
| `stp.related` | `true` / `false` |
| `stp.event.type` | STP event classification (root_bridge_change, topology_change, etc.) |
| `stp.vlan` | VLAN ID (if present) |
| `stp.interface` | Interface name (if present) |
| `stp.mac` | MAC address (if present) |

## Dashboard

The generated Gen 3 dashboard includes:

- **Header** — switches analyzed, total logs, STP event count
- **Key findings** — dynamic markdown summarizing root bridge instability, affected VLANs, top interfaces
- **STP Event Count** — single-value tile
- **Events by Severity** — bar chart
- **Events Over Time** — time series
- **STP Event Type Distribution** — pie chart
- **Top Affected VLANs** — bar chart
- **Top Affected Interfaces** — bar chart
- **Root Bridge Changes Over Time** — time series
- **STP Events by Switch** — bar chart
- **Recent Critical STP Events** — log table
- **All Log Entries** — full log table

> **Note**: The dashboard uses absolute timestamps matching the ingestion time window, so data always shows regardless of the dashboard time picker.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  Dell Switch     │     │  Log Parser      │     │  Dynatrace          │
│  Syslog Files    │────▶│  (BSD / RFC5424) │────▶│  Log Ingest API     │
│  (.txt / .log)   │     │  + STP Analysis  │     │  (Grail Storage)    │
└─────────────────┘     └──────────────────┘     └─────────┬───────────┘
                                                           │
                         ┌──────────────────┐              │
                         │  OAuth PKCE Flow │◀─────────────┘
                         │  (Browser Auth)  │
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │  Document API    │
                         │  (Gen 3 Dashboard│
                         │   Creation)      │
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
