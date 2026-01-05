# RedAudit Usage Guide

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](USAGE.es.md)

**Audience:** Pentesters, Security Operators, Blue Teamers
**Scope:** CLI limits, usage examples, configuration, runtime options
**What this document does NOT cover:** Network theory, exploit development
**Source of Truth:** `redaudit --help`

---

## 1. Quick Start

Run these commands to get started immediately.

### Interactive Wizard (Best for first time)

Step-by-step navigation with a "< Go Back" option (v4.0.1+). Webhook configuration and network discovery options are available in the wizard; SIEM exports are generated automatically when encryption is off.
Phase 0 low-impact enrichment can be enabled from the wizard (default off) or via `--low-impact-enrichment`.

```bash
sudo redaudit
```

### Fast Inventory (LAN)

```bash
sudo redaudit -t 192.168.1.0/24 -m fast --yes
```

### Standard Audit (Single Host)

```bash
sudo redaudit -t 10.10.10.5 -m normal --html-report
```

```bash
sudo redaudit -t 192.168.56.101 \
  --mode full \
  --udp-mode full \
  --threads 16 \
  --no-prevent-sleep
```

**Artifacts:** JSON/TXT, optional HTML, PCAP (deep scan + tcpdump), playbooks (when findings match categories and encryption is off).

### Authorized Pentest (Stealth/Corporate)

Focus on low noise, reliable artifacts, and encryption for chain of custody.

```bash
sudo redaudit -t 10.20.0.0/24 \
  --stealth \
  --encrypt \
  --encrypt-password "ClientProject2025!"
```

**Notes:** `stealth` enforces T1 timing and 5s delay. Encryption disables HTML/JSONL/playbooks/manifest.

### Blue Team / NetOps (Discovery)

Focus on identifying unauthorized devices and network leaks.

```bash
sudo redaudit -t 172.16.0.0/16 \
  --mode fast \
  --net-discovery arp,mdns,upnp \
  --topology \
  --allow-non-root
```

**Notes:** `allow-non-root` runs in limited mode; OS detection, UDP scans, and tcpdump captures may fail.

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

### VPN Gateway Discovery

Identify VPN interfaces and endpoints within a report:

```bash
cat redaudit_*.json | jq '.hosts[] | select(.asset_type == "vpn")'
```

---

## 3. CLI Flags Reference

Grouped by operational function. Verified against the current codebase.

### Scan Scope & Intensity

| Flag | Description |
| :--- | :--- |
| `-t, --target CIDR` | IP, range, or CIDR (comma-separated supported) |
| `-m, --mode` | `fast` (host discovery), `normal` (top 100), `full` (all ports + scripts/OS detection) |
| `-j, --threads N` | Parallel hosts 1-16 (Auto-detected) |
| `--rate-limit S` | Delay between hosts in seconds (applies jitter) |
| `--deep-scan-budget N` | Max hosts eligible for aggressive deep scan (0 = unlimited) |
| `--identity-threshold N` | Minimum identity score to skip deep scan |
| `--stealth` | Force T1 timing, 1 thread, 5s delay |
| `--dry-run` | Show commands without executing them |

### Connectivity & Proxy

| Flag | Description |
| :--- | :--- |
| `--proxy URL` | SOCKS5 proxy (socks5://host:port) |
| `--ipv6` | Enable IPv6-only scanning mode |
| `--no-prevent-sleep` | Do not inhibit system sleep |

### Advanced Discovery

| Flag | Description |
| :--- | :--- |
| `--yes` | Auto-confirm all prompts |
| `--net-discovery` | Broadcast protocols (dhcp,netbios,mdns,upnp,arp,fping) |
| `--topology` | L2/L3 topology mapping (routes/gateways) |
| `--udp-mode` | `quick` (priority ports) or `full` (top ports) |
| `--redteam` | Add AD/Kerberos/SNMP recon techniques |
| `--redteam-active-l2` | Enable noisier L2 active probing |
| `--agentless-verify` | Enable agentless verification (SMB/RDP/LDAP/SSH/HTTP) |
| `--no-agentless-verify` | Disable agentless verification (overrides defaults) |
| `--agentless-verify-max-targets N` | Cap agentless verification targets (1-200, default: 20) |

### Reporting & Integration

| Flag | Description |
| :--- | :--- |
| `-o, --output DIR` | Custom output directory |
| `--lang` | Interface/report language (en/es) |
| `--html-report` | Generate interactive dashboard (HTML) |
| `--webhook URL` | Send webhook alerts (JSON) for high/critical findings |
| `--nuclei` | Enable Nuclei template scanning (requires `nuclei`; runs in full mode only) |
| `--no-nuclei` | Disable Nuclei template scanning (overrides persisted defaults) |
| `--no-vuln-scan` | Skip Nikto/Web vulnerability scanning |
| `--cve-lookup` | Correlate services with NVD CVE data |

### Security & Privacy

| Flag | Description |
| :--- | :--- |
| `-e, --encrypt` | Encrypt all sensitive artifacts (AES-128) |
| `--allow-non-root` | Run without sudo (limited capability) |

### Configuration

| Flag | Description |
| :--- | :--- |
| `--save-defaults` | Save current CLI args to `~/.redaudit/config.json` |
| `--defaults {ask,use,ignore}` | Control how persisted defaults are applied |
| `--use-defaults` | Load args from config.json automatically |
| `--ignore-defaults` | Force factory defaults |
| `--no-color` | Disable colored output |
| `--skip-update-check` | Skip startup update check |

---

## 4. Output & Paths

**Default Path:**
`<Documents>/RedAuditReports/RedAudit_<TIMESTAMP>/` (uses the invoking user's Documents directory; `Documents`/`Documentos` depending on the system)

To change the default permanently:

```bash
sudo redaudit --output /opt/redaudit/reports --save-defaults --yes
```

**Artifact Manifest:**

- **.json**: Full data model (always created).
- **.txt**: Human readable summary.
- **.html**: Dashboard (requires `--html-report`, disabled by `--encrypt`).
- **.jsonl**: Streaming events for SIEM (disabled by `--encrypt`).
- **playbooks/*.md**: Remediation guides (disabled by `--encrypt`).
- **run_manifest.json**: Output manifest (disabled by `--encrypt`).
- **.pcap**: Packet captures (only if Deep Scan + tcpdump + Root).
- **session_*.log**: Raw terminal output with color codes (in `session_logs/`).
- **session_*.txt**: Clean plain-text terminal output (in `session_logs/`).

**Progress/ETA Notes:**

- `ETA≤` shows the timeout-based upper bound for the current batch.
- `ETA≈` is a dynamic estimate based on completed hosts.

---

## 5. Common Errors

**`Permission denied` (socket error)**
RedAudit needs root for:

- OS detection and some Nmap scan types
- UDP scanning and raw socket probes
- PCAP generation via `tcpdump`
**Fix:** Run with `sudo` or use `--allow-non-root` (limited mode).

**`nmap: command not found`**
Dependencies missing from PATH.
**Fix:** Run `sudo bash redaudit_install.sh` or check `/usr/local/lib/redaudit`.

**`testssl.sh not found`**
TLS deep checks are skipped in full mode.
**Fix:** Run `sudo bash redaudit_install.sh` to install the core toolchain.

**`Decryption failed`**
Missing `.salt` file or wrong password.
**Fix:** Ensure the `.salt` file is in the same directory as the `.enc` file.

---

[Back to README](../README.md) | [Documentation Index](INDEX.md)
