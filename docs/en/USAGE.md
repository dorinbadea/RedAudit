# RedAudit Usage Guide

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](../es/USAGE.md)

## CLI Reference

RedAudit is designed for stateless execution via command-line arguments.

### Syntax

```bash
sudo redaudit [OPTIONS]
# Or via Python module (v2.6+)
sudo python -m redaudit [OPTIONS]
```

Note: for limited mode without sudo/root, add `--allow-non-root` (some scan features may fail or be skipped).

### Core Arguments

| Flag | Description |
| :--- | :--- |
| `-t`, `--target` | Target IP, subnet (CIDR), or comma-separated list. |
| `-m`, `--mode` | Scan intensity: `fast` (discovery), `normal` (top ports), `full` (all ports + scripts). |
| `-o`, `--output` | Specify output directory. Default: `~/Documents/RedAuditReports`. |
| `--lang` | Interface language: `en` (default), `es`. |
| `-y`, `--yes` | Skip legal warning confirmation (use with caution). |

### Performance & Evasion

| Flag | Description |
| :--- | :--- |
| `-j`, `--threads <N>` | Set thread pool size for concurrent host scanning (1-16, default: 6). |
| `--rate-limit` | Seconds to sleep between host scans (float). Includes ±30% jitter. |
| `--prescan` | Enable fast asyncio pre-scan before nmap. |
| `--prescan-ports` | Port range for pre-scan (default: 1-1024). |
| `--prescan-timeout` | Pre-scan connection timeout in seconds (default: 0.5). |
| `--udp-mode` | UDP scan mode: `quick` (default) or `full`. |
| `--udp-ports` | Number of top UDP ports to scan in `--udp-mode full` (50-500, default: 100). |
| `--skip-update-check` | Skip update check at startup. |
| `--no-deep-scan` | Disable adaptive deep scan. |
| `--no-vuln-scan` | Disable web vulnerability scanning. |
| `--no-txt-report` | Disable TXT report generation. |
| `--max-hosts` | Maximum number of discovered hosts to scan (default: all). |

### v3.0 Features

| Flag | Description |
| :--- | :--- |
| `--ipv6` | Enable IPv6-only scanning mode. |
| `--proxy URL` | SOCKS5 proxy for pivoting (e.g., `socks5://pivot:1080`). |
| `--diff OLD NEW` | Compare two JSON reports and generate delta analysis. |
| `--cve-lookup` | Enable CVE correlation via NVD API. |
| `--nvd-key KEY` | NVD API key for faster rate limits (optional). |
| `--allow-non-root` | Run in limited mode without sudo (no OS detection/pcap; some scans may fail). |

### v3.1+ Features

| Flag | Description |
| :--- | :--- |
| `--topology` | Enable topology discovery (ARP/VLAN/LLDP + gateway/routes). |
| `--no-topology` | Disable topology discovery (override persisted defaults). |
| `--topology-only` | Run topology discovery only (skip host scanning). |
| `--save-defaults` | Save current CLI settings as persistent defaults (`~/.redaudit/config.json`). |

### v3.2+ Features

| Flag | Description |
| :--- | :--- |
| `--net-discovery [PROTO,...]` | Enable enhanced network discovery (all, or comma-separated: dhcp,netbios,mdns,upnp,arp,fping). |
| `--redteam` | Include opt-in Red Team recon block in net discovery (best-effort, slower/noisier). |
| `--net-discovery-interface IFACE` | Network interface for net discovery and L2 captures (e.g., eth0). |
| `--redteam-max-targets N` | Max target IPs sampled for redteam checks (1-500, default: 50). |
| `--snmp-community COMMUNITY` | SNMP community for SNMP walking (default: public). |
| `--dns-zone ZONE` | DNS zone hint for AXFR attempt (e.g., corp.local). |
| `--kerberos-realm REALM` | Kerberos realm hint (e.g., CORP.LOCAL). |
| `--kerberos-userlist PATH` | Optional userlist for Kerberos userenum (requires kerbrute; use only with authorization). |
| `--redteam-active-l2` | Enable additional L2-focused checks that may be noisier (bettercap/scapy sniff; requires root). |

### v3.2.3 Features

| Flag | Description |
| :--- | :--- |
| `--stealth` | Stealth mode: paranoid nmap timing (T1), single-thread, 5s+ delay. For enterprise networks with IDS/rate limiters. |

### v3.3.0 Features

| Flag | Description |
| :--- | :--- |
| `--html-report` | Generate interactive HTML dashboard with charts and sortable tables (works offline). |
| `--webhook URL` | Send real-time alerts for High/Critical findings to a webhook URL (Slack/Teams/Discord). |

### v3.4.0 Features

**Remediation Playbooks** are now automatically generated after each scan. Playbooks provide actionable guidance for remediating detected findings.

| Category | Content |
| :--- | :--- |
| TLS Hardening | Cipher suites, protocol versions, certificate issues |
| HTTP Headers | Missing HSTS, CSP, X-Frame-Options, etc. |
| CVE Remediation | Patch guidance with NVD links |
| Web Hardening | Directory listing, server banners, default pages |
| Port Hardening | Telnet, FTP, SMBv1, SNMP public community |

**Output**: `<output_dir>/playbooks/` directory with one Markdown file per category per host.

**Notes**: Playbooks are deduplicated (one per host + category) and are skipped when report encryption is enabled (`--encrypt`).

### Security

| Flag | Description |
| :--- | :--- |
| `-e`, `--encrypt` | Encrypt output artifacts with AES-128. Prompts for password if not provided. |
| `--encrypt-password` | Password for encryption (non-interactive mode). |
| `-V`, `--version` | Display version information and exit. |

## Examples

**1. Standard Subnet Audit**
Enumerates services on a Class C subnet with default concurrency.

```bash
sudo redaudit -t 192.168.1.0/24 --mode normal --yes
```

**2. High-Stealth Targeted Scan**
Scans a single host with rate limiting enabled to reduce noise.

```bash
sudo redaudit -t 10.0.0.50 --rate-limit 1.5 --mode normal --yes
```

**3. Full Audit with Encryption**
Deep scan with encrypted reporting for chain-of-custody.

```bash
sudo redaudit -t 192.168.1.100 --mode full --encrypt --yes
```

**4. Fast Pre-scan on Large Range**
Use asyncio pre-scan for fast port discovery before nmap.

```bash
sudo redaudit -t 192.168.1.0/24 --prescan --prescan-ports 1-1024 --yes
```

**5. IPv6 Network Scan (v3.0)**
Scan an IPv6 network segment.

```bash
sudo redaudit -t "2001:db8::/64" --ipv6 --mode normal --yes
```

**6. Compare Two Scan Reports (v3.0)**
Generate a differential analysis showing network changes.

```bash
redaudit --diff ~/reports/monday.json ~/reports/friday.json
```

**7. Scan Through Proxy (v3.0)**
Pivot through a SOCKS5 proxy for internal network access.

```bash
sudo redaudit -t 10.0.0.0/24 --proxy socks5://pivot-host:1080 --yes
```

**8. CVE Correlation Scan (v3.0)**
Enrich results with NIST NVD vulnerability data.

```bash
sudo redaudit -t 192.168.1.0/24 --cve-lookup --nvd-key YOUR_KEY --yes
```

**9. Enhanced Net Discovery (v3.2)**
Broadcast-based discovery to reveal additional DHCP servers, hostnames, and L2 signals.

```bash
sudo redaudit -t 192.168.1.0/24 --net-discovery --redteam --net-discovery-interface eth0 --yes
```

**10. HTML Dashboard & Webhook Alerts (v3.3)**
Generate a visual report and alert on critical findings.

```bash
sudo redaudit -t 192.168.1.0/24 --html-report --webhook https://hooks.slack.com/services/XXX --yes
```

### Reports & Encryption

Reports are saved in timestamped subfolders (v2.8+): `RedAudit_YYYY-MM-DD_HH-MM-SS/`

Each scan session creates its own folder with:

- **Plain**: `.json` and `.txt`.
- **Encrypted**: `.json.enc`, `.txt.enc`, and `.salt`.
- **SIEM/AI exports (v3.1)**: `findings.jsonl`, `assets.jsonl`, `summary.json` (generated only when encryption is disabled).
- **PCAP**: Traffic capture files (when deep scan runs and capture tools are available).

**New fields in v3.1.4**:

- `severity_note`: Explanation when severity was adjusted (e.g., "RFC-1918 disclosure on private network")
- `potential_false_positives`: Array of detected contradictions from cross-validation
- `pcap_file`: Portable relative filename for PCAP captures

**New fields in v3.2.0**:

- `net_discovery`: Optional enhanced network discovery block (only when `--net-discovery` is enabled)
- `net_discovery.dhcp_servers[].domain` / `net_discovery.dhcp_servers[].domain_search`: Best-effort domain hints from DHCP responses
- `net_discovery.redteam`: Extended recon output when `--redteam` is enabled (SNMP/SMB/RPC/LDAP/Kerberos/DNS + passive L2 signals)

To decrypt results:

```bash
python3 redaudit_decrypt.py /path/to/report.json.enc
```

This will generate `.decrypted` files (or restore original extension) after password verification.

### Logging

Debug logs are stored in `~/.redaudit/logs/`. Check these files if the scan fails or behaves unexpectedly.

## CVE Correlation Setup

RedAudit can enrich scan results with CVE data from NIST's National Vulnerability Database (NVD).
This enrichment depends on detected service versions (or versioned CPEs); when version is unknown, RedAudit skips that port to avoid overly broad results.

### API Key Configuration

The NVD API has rate limits:

- **Without key**: 5 requests per 30 seconds
- **With key**: 50 requests per 30 seconds (10x faster)

### Getting an API Key

1. Visit: <https://nvd.nist.gov/developers/request-an-api-key>
2. Register with your email (FREE)
3. Receive your UUID-format API key

### Configuration Methods

**Option 1: During Installation**

The installer prompts for the API key:

```bash
sudo ./redaudit_install.sh
```

**Option 2: Environment Variable**

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
export NVD_API_KEY="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**Option 3: Config File**

Create `~/.redaudit/config.json`:

**Note**: The `version` field in `~/.redaudit/config.json` is the **config schema version** (currently `3.2.3`) and does not need to match the RedAudit application version (v3.4.0).

```json
{
  "version": "3.2.3",
  "nvd_api_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "defaults": {
    "threads": 6,
    "rate_limit": 1.5,
    "udp_mode": "full",
    "udp_top_ports": 200,
    "topology_enabled": true,
    "lang": "en",
    "output_dir": "~/Documents/RedAuditReports"
  }
}
```

**Option 4: Command Line**

Pass the key directly (not persisted):

```bash
sudo redaudit -t 192.168.1.0/24 --cve-lookup --nvd-key YOUR_KEY
```

### Usage

```bash
# With configured key
sudo redaudit -t 192.168.1.0/24 --cve-lookup

# Without key (slower rate limit)
sudo redaudit -t 192.168.1.0/24 --cve-lookup
```

## Performance & Stealth

### Rate Limiting

RedAudit allows you to set a delay (in seconds) between scanning hosts. **v2.7 adds ±30% random jitter** to this delay for IDS evasion.

- **0s (Default)**: Maximum speed. Best for internal audits where noise is not a concern.
- **1-5s**: Moderate stealth. Reduces the chance of triggering simple rate-limit firewalls.
- **>10s**: High stealth. Significantly slows down the audit but minimizes network congestion and detection risk.

### Pre-scan

Enable `--prescan` to use asyncio TCP connect for fast port discovery before invoking nmap:

```bash
sudo redaudit -t 192.168.1.0/24 --prescan --prescan-ports 1-1024 --yes
```

**Note on Heartbeat**: If you set a very high delay (e.g., 60s) with many threads, the scan might seem "frozen". Check the logs or the heartbeat status.

### CLI Execution Markers

RedAudit v2.8.0 strictly informs you about the commands being executed:

- **`[nmap] 192.168.x.x → nmap ...`**: Standard port scan.
- **`[deep] 192.168.x.x → combined ...`**: Deep Identity Scan execution (expect 90-140s duration).

### Adaptive Deep Scan & Traffic Capture

RedAudit automatically attempts an "Adaptive Deep Scan" on hosts that:

1. **Have >8 open ports**
2. **Have suspicious services** (socks, proxy, vpn, tor, nagios, etc.)
3. **Have very few ports (<=3)**
4. **Have open ports but no version information detected**

- **Adaptive Strategy**: Runs a 2-phase scan (TCP aggressive first, then UDP/OS fallback only if Phase 1 didn't find MAC/OS identity) to fingerprint complex hosts.
- **Traffic Capture**: As part of Deep Scan, if `tcpdump` is available, the tool captures a **50-packet snippet** (max 15s) from the host's traffic.
  - Saves `.pcap` files in your report directory.
  - If `tshark` is installed, a text summary of protocols is included in the JSON report.
  - *Defense*: The capture duration is strictly capped to prevent hanging.

---

RedAudit is licensed under **GPLv3**. See [LICENSE](../../LICENSE) for details.
