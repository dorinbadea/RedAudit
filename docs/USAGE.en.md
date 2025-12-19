# RedAudit Usage Guide

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](USAGE.es.md)

**Audience:** Pentesters, Security Operators, Blue Teamers
**Scope:** CLI limits, usage examples, configuration, runtime options
**What this document does NOT cover:** Network theory, exploit development
**Source of Truth:** `redaudit --help`

---

## 1. Quick Start

Run these commands to get started immediately.

**Interactive Wizard (Best for first time)**

New in v3.7: Configures Webhooks, SIEM, and Advanced Network Discovery interactively.

```bash
sudo redaudit
```

**Fast Inventory (LAN)**

```bash
sudo redaudit -t 192.168.1.0/24 -m fast --yes
```

**Standard Audit (Single Host)**

```bash
sudo redaudit -t 10.10.10.5 -m normal --html-report
```

---

## 2. Examples by Scenario

### Lab / CTF (Aggressive)

Focus on speed and maximum information gathering.

```bash
sudo redaudit -t 192.168.56.101 \
  --mode full \
  --udp-mode full \
  --threads 16 \
  --no-prevent-sleep
```

**Artifacts:** JSON, HTML, PCAP (if deep scan triggers), Playbooks.

### Authorized Pentest (Stealth/Corporate)

Focus on low noise, reliable artifacts, and encryption for chain of custody.

```bash
sudo redaudit -t 10.20.0.0/24 \
  --stealth \
  --encrypt \
  --encrypt-password "ClientProject2025!" \
  --html-report
```

**Notes:** `stealth` enforces T1 timing and 5s delay. Encryption disables HTML/JSONL.

### Blue Team / NetOps (Discovery)

Focus on identifying unauthorized devices and network leaks.

```bash
sudo redaudit -t 172.16.0.0/16 \
  --mode fast \
  --net-discovery arp,mdns,upnp \
  --topology \
  --allow-non-root
```

**Notes:** `allow-non-root` skips OS fingerprinting and PCAP.

### Red Team (Internal Recon)

Focus on Active Directory, Kerberos, and SNMP enumeration from a pivot point.

```bash
sudo redaudit -t 10.0.0.0/8 \
  --proxy socks5://127.0.0.1:1080 \
  --redteam \
  --redteam-active-l2 \
  --kerberos-realm CORP.LOCAL
```

**Risks:** `redteam-active-l2` uses active probing (bettercap/scapy) which may trigger IDS.

### CI/CD Pipeline (Checking Changes)

Differential analysis between two previous scans.

```bash
redaudit --diff reports/report_v1.json reports/report_v2.json
```

**Output:** Delta analysis showing New/Open/Closed/Changed ports. No scan is performed.

---

## 3. CLI Flags Reference

Grouped by operational function. Verified against the current codebase.

### Scan Scope & Intensity

| Flag | Description |
|:---|:---|
| `-t, --target CIDR` | IP, range, or CIDR (comma-separated supported) |
| `-m, --mode` | `fast` (ping), `normal` (top 1000), `full` (65k + scripts) |
| `-j, --threads N` | Parallel hosts 1-16 (Default: 6) |
| `--rate-limit S` | Delay between hosts in seconds (applies jitter) |
| `--stealth` | Force T1 timing, 1 thread, 5s delay |
| `--dry-run` | Show commands without executing them |

### Connectivity & Proxy

| Flag | Description |
|:---|:---|
| `--proxy URL` | SOCKS5 proxy (socks5://host:port) |
| `--ipv6` | Enable IPv6-only scanning mode |
| `--no-prevent-sleep`| Do not inhibit system sleep |

### Advanced Discovery

| Flag | Description |
|:---|:---|
| `--net-discovery` | Broadcast protocols (dhcp,netbios,mdns,upnp,arp,fping) |
| `--topology` | L2/L3 topology mapping (routes/gateways) |
| `--udp-mode` | `quick` (priority ports) or `full` (top ports) |
| `--redteam` | Add AD/Kerberos/SNMP recon techniques |
| `--redteam-active-l2` | Enable noisier L2 active probing |

### Reporting & Integration

| Flag | Description |
|:---|:---|
| `-o, --output DIR` | Custom output directory |
| `--html-report` | Generate interactive dashboard (HTML) |
| `--webhook URL` | Send findings to Slack/Teams/Discord |
| `--nuclei` | Enable Nuclei template scanning (requires `nuclei`; runs in full mode only) |
| `--no-nuclei` | Disable Nuclei template scanning (overrides persisted defaults) |
| `--no-vuln-scan` | Skip Nikto/Web vulnerability scanning |
| `--cve-lookup` | Correlate services with NVD CVE data |

### Security & Privacy

| Flag | Description |
|:---|:---|
| `-e, --encrypt` | Encrypt all sensitive artifacts (AES-128) |
| `--allow-non-root` | Run without sudo (limited capability) |
| `--searchsploit` | (Enabled by default in normal/full) |

### Configuration

| Flag | Description |
|:---|:---|
| `--save-defaults` | Save current CLI args to `~/.redaudit/config.json` |
| `--use-defaults` | Load args from config.json automatically |
| `--ignore-defaults` | Force factory defaults |
| `--no-color` | Disable colored output |
| `--skip-update-check` | Skip startup update check |

---

## 4. Output & Paths

**Default Path:**
`~/Documents/RedAuditReports/RedAudit_<TIMESTAMP>/`

To change the default permanently:

```bash
sudo redaudit --output /opt/redaudit/reports --save-defaults --yes
```

**Artifact Manifest:**

- **.json**: Full data model (always created).
- **.txt**: Human readable summary.
- **.html**: Dashboard (requires `--html-report`, disabled by `--encrypt`).
- **.jsonl**: Streaming events for SIEM (disabled by `--encrypt`).
- **.pcap**: Packet captures (only if Deep Scan + tcpdump + Root).
- **session.log**: Raw terminal output with color codes (in `session_logs/`).
- **session.txt**: Clean plain-text terminal output (in `session_logs/`).

---

## 5. Common Errors

**`Permission denied` (socket error)**
RedAudit needs root for:

- SYN Scan (`-sS`) output processing
- OS Fingerprinting (`-O`)
- PCAP generation
**Fix:** Run with `sudo` or use `--allow-non-root`.

**`nmap: command not found`**
Dependencies missing from PATH.
**Fix:** Run `sudo bash redaudit_install.sh` or check `/usr/local/lib/redaudit`.

**`Decryption failed`**
Missing `.salt` file or wrong password.
**Fix:** Ensure the `.salt` file is in the same directory as the `.enc` file.

---

[Back to README](../README.md) | [Documentation Index](INDEX.md)
