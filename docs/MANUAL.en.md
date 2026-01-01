# RedAudit User Manual

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](MANUAL.es.md)

**Audience:** Security analysts, penetration testers, system administrators
**Scope:** Installation, operation, output artifacts, security model
**What this document does NOT cover:** Exploitation techniques, code internals
**Source of Truth:** `redaudit --help`, `redaudit/core/auditor.py`

---

## 1. What RedAudit Is (and Is Not)

RedAudit is an **automated network auditing framework** for Linux (Debian-family). It orchestrates external tools (`nmap`, `whatweb`, `nikto`, `testssl.sh`, `nuclei`, `searchsploit`) into a unified pipeline and produces structured reports.

**It is:**

- A reconnaissance and vulnerability discovery orchestrator
- A report generator (JSON, TXT, HTML, JSONL)
- A tool for authorized security assessments

**It is NOT:**

- An exploitation framework
- A replacement for manual analysis
- Designed for Windows or macOS

---

## 2. Requirements and Permissions

| Requirement | Details |
| :--- | :--- |
| **OS** | Kali Linux, Debian 11+, Ubuntu 20.04+, Parrot OS |
| **Python** | 3.9+ |
| **Privileges** | `sudo` / root required for: OS detection, UDP scans, packet capture (tcpdump), ARP/L2 discovery |
| **Dependencies** | The installer provides the recommended toolchain (nmap, whatweb, nikto, nuclei, searchsploit, tcpdump, tshark, and others) and installs `testssl.sh` from GitHub |

**Limited mode:** `--allow-non-root` enables reduced functionality without root (OS detection, UDP, and tcpdump features may fail).

---

## 3. Installation

### Standard Install

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
source ~/.zshrc  # or ~/.bashrc
```

The installer:

1. Installs system dependencies via `apt`
2. Copies code to `/usr/local/lib/redaudit`
3. Creates the `redaudit` shell alias
4. Prompts for language preference (EN/ES)

### Manual Install (without installer)

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo apt install nmap whatweb nikto tcpdump tshark exploitdb python3-nmap python3-cryptography
sudo python3 -m redaudit --help
```

TLS deep checks require `testssl.sh`. The installer installs it from GitHub as part of the core toolchain.

### Docker (optional)

Run the official container image via GHCR:

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest

docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$(pwd)/reports:/reports" \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

### Update

RedAudit checks for updates on startup (interactive mode). To skip: `--skip-update-check`.

---

## 4. Wizard Profile Selector (v3.9.0+)

When running `sudo redaudit` in interactive mode, the wizard asks which **audit profile** to use:

### Express

**Use case:** Quick network discovery for asset inventory.

- **Mode**: `fast` (host discovery only, no port scanning)
- **Features disabled**: Vulnerability scans, Nuclei, CVE correlation, agentless verification
- **Discovery enabled**: Topology + Network Discovery
- **Timing**: Fast
- **Questions**: Minimal (auditor name, output dir)
- **Best for**: Initial reconnaissance, counting live hosts
- **Detection heuristics**:
  - **Asset type guessing**: Hints from hostname/vendor/agentless signals (e.g., router, switch, printer, media, IoT, VPN).
  - **VPN Heuristics**: Detection based on gateway MAC-IP mismatch, VPN ports (500, 4500, 1194, 51820), and hostname patterns (`tunnel`, `ipsec`, etc.).

### Standard

**Use case:** Balanced vulnerability assessment.

- **Mode**: `normal` (nmap `-F` / top 100 ports + version detection)
- **Features**: web vuln scanning enabled (whatweb; nikto/testssl only in full), searchsploit if available, topology + network discovery enabled
- **Timing**: Chosen via preset (Stealth/Normal/Aggressive)
- **Questions**: Profile selection + timing + auditor/output prompts
- **Best for**: Most security audits

### Exhaustive

**Use case**: Maximum discovery and correlation for comprehensive assessments.

- **Mode**: `completo` (all 65535 ports + scripts/OS detection)
- **Threads**: MAX (16) or reduced in Stealth preset (2)
- **UDP**: top 500 ports for deep scan (only when triggered)
- **Features enabled**: Vulnerabilities, Topology, Net Discovery, Red Team, Agentless Verification; Nuclei if installed
- **CVE Correlation**: Enabled if NVD API key is configured
- **Timing**: Chosen via preset (Stealth/Normal/Aggressive)
- **Questions**: Only auditor name and output dir (all else auto-configured)
- **Best for**: Penetration testing, compliance audits, pre-production validation

### Custom

**Use case:** Full control over all configuration options.

- **Behavior**: Full 8-step wizard with back navigation
- **Questions**: Scan mode, threads/rate, vulnerability scan, CVE lookup, output/auditor, UDP/topology, net discovery/red team, agentless verification + webhook
- **Best for**: Tailored scans with specific requirements

---

## 5. Operation

### Execution Modes

| Mode | Invocation | Behavior |
| :--- | :--- | :--- |
| **Interactive** | `sudo redaudit` | Text-based wizard; prompts for target, mode, options |
| **Non-interactive** | `sudo redaudit --target X --yes` | Direct execution; all options via CLI flags |

### Scan Modes (`--mode`)

| Mode | nmap Behavior | Additional Tools |
| :--- | :--- | :--- |
| `fast` | `-sn` (host discovery only) | None |
| `normal` | Top 100 ports (`-F`), version detection | whatweb, searchsploit (if available) |
| `full` | All 65535 ports, scripts, OS detection | whatweb, nikto, testssl.sh, nuclei (installed and explicitly enabled), searchsploit |

**Timeout behavior:** Host scans are bounded by the nmap `--host-timeout` for the selected mode (full: 300s). RedAudit
enforces a hard timeout and marks the host as no-response if it is exceeded, keeping scans responsive on IoT/embedded
devices.

### Adaptive Deep Scan

When enabled (default), RedAudit performs additional scanning on hosts where initial results are ambiguous or indicate virtual infrastructure:

**Trigger conditions:**

- Fewer than 3 open ports found (when identity is weak)
- Services identified as `unknown` or `tcpwrapped`
- MAC/vendor information not obtained
- **VPN Gateway Detection**: Host shares the MAC address with the gateway but has a different IP (virtual interface)

**Behavior:**

0. (Optional) Phase 0 low-impact enrichment (DNS reverse, mDNS unicast, SNMP sysDescr) when `--low-impact-enrichment` is enabled
1. Phase 1: Aggressive TCP (`-A -p- -sV -Pn`)
2. Phase 2a: Priority UDP probe (17 common ports including 500/4500)
3. Phase 2b: UDP top-ports (`--udp-ports`) when mode is `full` and identity is still weak
4. Quiet hosts with vendor hints and zero open ports may get a short HTTP/HTTPS probe on common paths

Disable with `--no-deep-scan`.

SmartScan uses an identity score (default threshold: 3; full mode uses 4) to decide whether to escalate.

VPN classification is handled by asset typing heuristics (gateway MAC/IP, VPN ports, hostname patterns) after scanning.

### Agentless Verification (Optional)

When enabled, RedAudit runs lightweight Nmap scripts against hosts that expose SMB/RDP/LDAP/SSH/HTTP to enrich identity
data (OS hints, domain info, titles/headers, and basic fingerprints). This does **not** use credentials and is opt-in
to keep noise
predictable.

- Enable via wizard prompt or `--agentless-verify`.
- Limit scope with `--agentless-verify-max-targets` (default: 20).

---

## 5. CLI Reference (Complete)

Flags verified against `redaudit --help` (v3.9.9):

### Core

| Flag | Description |
| :--- | :--- |
| `-t, --target CIDR` | Target network(s), comma-separated |
| `-m, --mode {fast,normal,full}` | Scan intensity (default: normal) |
| `-o, --output DIR` | Output directory (default: `~/Documents/RedAuditReports`) |
| `-y, --yes` | Skip confirmation prompts |
| `-V, --version` | Print version and exit |

### Performance

| Flag | Description |
| :--- | :--- |
| `-j, --threads 1-16` | Concurrent host workers (default: 6) |
| `--rate-limit SECONDS` | Delay between hosts (±30% jitter applied) |
| `--max-hosts N` | Limit hosts to scan |
| `--no-deep-scan` | Disable adaptive deep scan |
| `--low-impact-enrichment` | Low-impact enrichment (DNS/mDNS/SNMP) before TCP scanning |
| `--deep-scan-budget N` | Max hosts that can run aggressive deep scan per run (0 = unlimited) |
| `--identity-threshold N` | Minimum identity_score to skip deep scan (default: 3) |
| `--prescan` | Reserved flag (currently stored in config; no pre-scan executed) |
| `--prescan-ports RANGE` | Reserved (default: 1-1024) |
| `--prescan-timeout SECONDS` | Reserved (default: 0.5) |
| `--stealth` | T1 timing, 1 thread, 5s delay (detection-sensitive environments) |

### UDP Scanning

| Flag | Description |
| :--- | :--- |
| `--udp-mode {quick,full}` | quick = priority ports only; full = top N ports |
| `--udp-ports N` | Number of top ports for full mode (50-500, default: 100) |

### Topology & Discovery

| Flag | Description |
| :--- | :--- |
| `--topology` | Enable L2/L3 topology discovery |
| `--no-topology` | Disable topology discovery |
| `--topology-only` | Run topology only, skip host scanning |
| `--net-discovery [PROTOCOLS]` | Broadcast discovery (all, or: dhcp,netbios,mdns,upnp,arp,fping) |
| `--net-discovery-interface IFACE` | Interface for discovery |
| `--redteam` | Include Red Team techniques (SNMP, SMB, LDAP, Kerberos) |
| `--redteam-max-targets N` | Max targets for redteam checks (default: 50) |
| `--redteam-active-l2` | Enable noisier L2 checks (bettercap/scapy) |
| `--snmp-community COMMUNITY` | SNMP community for SNMP walking (default: public) |
| `--dns-zone ZONE` | DNS zone hint for AXFR attempts (optional) |
| `--kerberos-realm REALM` | Kerberos realm hint (optional) |
| `--kerberos-userlist PATH` | Userlist for Kerberos user enumeration (optional; requires kerbrute) |

### Security

| Flag | Description |
| :--- | :--- |
| `-e, --encrypt` | Encrypt reports (AES-128-CBC via Fernet) |
| `--encrypt-password PASSWORD` | Password for encryption (or random generated) |
| `--allow-non-root` | Run without sudo (limited functionality) |

### Reporting

| Flag | Description |
| :--- | :--- |
| `--html-report` | Generate interactive HTML dashboard |
| `--webhook URL` | POST alerts for high/critical findings |
| `--no-txt-report` | Skip TXT report generation |
| `--no-vuln-scan` | Skip nikto/web vulnerability scanning |
| `--nuclei` | Enable Nuclei template scanning (requires `nuclei`) |
| `--no-nuclei` | Disable Nuclei (overrides defaults) |

### Verification (Agentless)

| Flag | Description |
| :--- | :--- |
| `--agentless-verify` | Enable agentless verification (SMB/RDP/LDAP/SSH/HTTP) |
| `--no-agentless-verify` | Disable agentless verification (overrides defaults) |
| `--agentless-verify-max-targets N` | Cap verification targets (1-200, default: 20) |

### CVE Correlation

| Flag | Description |
| :--- | :--- |
| `--cve-lookup` | Enable NVD API correlation |
| `--nvd-key KEY` | API key for faster rate limits |

### Comparison

| Flag | Description |
| :--- | :--- |
| `--diff OLD NEW` | Compare two JSON reports (no scan performed) |

### Other

| Flag | Description |
| :--- | :--- |
| `--dry-run` | Print commands without executing |
| `--no-prevent-sleep` | Don't inhibit system sleep during scan |
| `--ipv6` | IPv6-only mode |
| `--proxy URL` | SOCKS5 proxy (socks5://host:port) |
| `--lang {en,es}` | Interface language |
| `--no-color` | Disable colored output |
| `--save-defaults` | Save current settings to ~/.redaudit/config.json |
| `--defaults {ask,use,ignore}` | Control how persisted defaults are applied |
| `--use-defaults` | Use saved defaults without prompting |
| `--ignore-defaults` | Ignore saved defaults |
| `--skip-update-check` | Skip update check at startup |

---

## 6. Output Artifacts

Default output path: `~/Documents/RedAuditReports/RedAudit_YYYY-MM-DD_HH-MM-SS/`

### Generated Files

| File | Condition | Description |
| :--- | :--- | :--- |
| `redaudit_*.json` | Always | Complete structured results |
| `redaudit_*.txt` | Unless `--no-txt-report` | Human-readable summary |
| `report.html` | If `--html-report` | Interactive dashboard |
| `findings.jsonl` | If encryption disabled | SIEM-ready JSONL events (ECS-aligned via configs) |
| `assets.jsonl` | If encryption disabled | Asset inventory |
| `summary.json` | If encryption disabled | Dashboard metrics |
| `run_manifest.json` | If encryption disabled | Session metadata |
| `playbooks/*.md` | If encryption disabled | Remediation guides |
| `traffic_*.pcap` | If deep scan triggers and tcpdump available | Packet captures |
| `session_logs/session_*.log` | Always | Session logs (raw with ANSI) |
| `session_logs/session_*.txt` | Always | Session logs (clean text) |

### Encryption Behavior

When `--encrypt` is used:

- `.json` and `.txt` become `.json.enc` and `.txt.enc`
- A `.salt` file is created alongside each encrypted file
- **Plaintext artifacts are NOT generated:** HTML, JSONL, playbooks, and manifest files are skipped for security

**Decryption:**

```bash
python3 redaudit_decrypt.py /path/to/report.json.enc
```

---

## 7. Security Model

### Encryption

- Algorithm: AES-128-CBC (Fernet specification)
- Key derivation: PBKDF2-HMAC-SHA256 with random salt
- Password policy: Interactive prompts enforce 12+ characters with complexity requirements; `--encrypt-password` is not validated

### Privilege Model

- Root required for: nmap OS detection, tcpdump, ARP scanning
- Files created with 0o600 permissions (owner-only read/write)
- No background services or daemons installed

### Input Validation

- All CLI arguments validated against type and range constraints
- No `shell=True` in subprocess calls
- Target CIDR validated before use

---

## 8. Integration

### SIEM Ingestion

See [SIEM_INTEGRATION.en.md](SIEM_INTEGRATION.en.md) for full setup guides (Elastic Stack and other SIEMs).

When encryption is disabled, `findings.jsonl` provides SIEM-friendly JSONL events (ECS-aligned fields via the bundled configs).
The Splunk HEC example below is optional and requires external Splunk configuration.

```bash
# Elasticsearch bulk ingest
cat findings.jsonl | curl -X POST "localhost:9200/redaudit/_bulk" \
  -H 'Content-Type: application/x-ndjson' --data-binary @-

# Splunk HEC
cat findings.jsonl | while read line; do
  curl -k "https://splunk:8088/services/collector" \
    -H "Authorization: Splunk TOKEN" -d "{\"event\":$line}"
done
```

### Webhook Alerts

`--webhook URL` sends HTTP POST for each high/critical finding. Compatible with endpoints that accept JSON payloads (e.g., Slack, Teams, PagerDuty).

---

## 9. Troubleshooting

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| Permission denied | Running without sudo | Use `sudo redaudit` |
| nmap: command not found | Missing dependency | Run `sudo bash redaudit_install.sh` |
| Decryption failed: Invalid token | Wrong password or corrupted .salt | Verify password; ensure .salt file exists |
| Scan appears frozen | Deep scan or slow host | Check `session_logs/` for the active tool; reduce scope with `--max-hosts` |
| No playbooks generated | Encryption enabled | Playbooks require `--encrypt` to be disabled |

See [TROUBLESHOOTING.en.md](TROUBLESHOOTING.en.md) for complete error reference.

---

## 10. External Tools

RedAudit orchestrates (does not modify or install):

| Tool | Invocation Condition | Report Field |
| :--- | :--- | :--- |
| `nmap` | Always | `hosts[].ports` |
| `whatweb` | HTTP/HTTPS detected | `vulnerabilities[].whatweb` |
| `nikto` | HTTP/HTTPS + full mode | `vulnerabilities[].nikto_findings` |
| `testssl.sh` | HTTPS + full mode | `vulnerabilities[].testssl_analysis` |
| `nuclei` | HTTP/HTTPS + full mode (if installed and enabled) | `vulnerabilities[].nuclei_findings` |
| `searchsploit` | Services with version detected | `ports[].known_exploits` |
| `tcpdump` | Deep scan triggers | `deep_scan.pcap_capture` |
| `tshark` | After tcpdump capture | `deep_scan.tshark_summary` |

---

[Back to README](../README.md) | [Documentation Index](INDEX.md)
