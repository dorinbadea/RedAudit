# RedAudit Usage Guide

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](USAGE.es.md)

**Audience:** Pentesters, security operators, and Blue Teamers.

**Scope:** CLI limits, usage examples, configuration, and runtime options.

**What this document does NOT cover:** Network theory and exploit development.

**Source of Truth:** `redaudit --help`

---

## 1. Quick Start

Run these commands to get started immediately.

### Interactive Wizard (Best for first time)

Step-by-step navigation with a "Cancel" option (v4.0.1+). Webhook configuration and network discovery options are available in the wizard; SIEM exports are generated automatically when encryption is off. If saved credentials are detected, the wizard offers to load them and then asks if you want to add more.
Phase 0 low-impact enrichment can be enabled from the wizard (default off) or via `--low-impact-enrichment`.
Manual target entry accepts comma-separated CIDR, IP, or range values.
The wizard prints normalized targets with estimated host counts before you confirm the run.

```bash
sudo redaudit
```

**Wizard modes (short):**

- **fast**: Discovery only, lowest noise, fastest.
- **normal**: Top ports, balanced time vs coverage (recommended default).
- **full**: All ports + scripts + web tools, slowest and noisiest.

**Timing presets (wizard):**

- **Stealth**: Slowest, lowest noise.
- **Normal**: Balanced speed and reliability.
- **Aggressive**: Fastest, more noise; can miss slow/filtered services.

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
  --threads 100 \
  --no-prevent-sleep
```

**Artifacts:** JSON/TXT, optional HTML, JSONL, run manifest, PCAP (deep scan + tcpdump), playbooks (when findings match categories and encryption is off).

## 2. Scenario Examples

Examples aligned with common audit workflows. Adjust timing and encryption based on client requirements.

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

Note: If the VPN is inactive, the VPN interface can appear as a separate asset with the same MAC as the gateway and no open ports. This is expected.

---

## 3. CLI Flags Reference

Grouped by operational function. Verified against the current codebase.

### Scan Scope & Intensity

| Flag | Description |
| :--- | :--- |
| `-t, --target CIDR` | IP, range, or CIDR (comma-separated supported) |
| `-m, --mode` | `fast` (host discovery), `normal` (top 100), `full` (all ports + scripts/OS detection) |
| `-j, --threads N` | Parallel hosts 1-100 (auto-detected; fallback 6) |
| `--rate-limit S` | Delay between hosts in seconds (±30% jitter applied) |
| `--deep-scan-budget N` | Max hosts eligible for aggressive deep scan (0 = unlimited) |
| `--identity-threshold N` | Minimum identity score to skip deep scan (0-100) |
| `--stealth` | Force T1 timing, 1 thread, 5s delay |
| `--dry-run` | Show commands without executing them |
| `--profile {fast,balanced,full}` | Set Nuclei scan intensity/speed (v4.11+) |
| `--dead-host-retries N` | Abandon host after N consecutive timeouts (v4.13+) |

### Connectivity & Proxy

| Flag | Description |
| :--- | :--- |
| `--proxy URL` | SOCKS5 proxy (socks5://host:port; requires proxychains4, TCP only) |
| `--ipv6` | Enable IPv6-only scanning mode |
| `--no-prevent-sleep` | Do not inhibit system sleep |

**Note:** `--proxy` wraps external tools with `proxychains4` and only affects TCP connect-based probes. UDP/ARP/ICMP discovery remains direct.

### Advanced Discovery

| Flag | Description |
| :--- | :--- |
| `--yes` | Auto-confirm all prompts |
| `--net-discovery` | Broadcast protocols (dhcp,netbios,mdns,upnp,arp,fping) |
| `--topology` | L2/L3 topology mapping (routes/gateways) |
| `--hyperscan-mode MODE` | `auto`, `connect`, or `syn` (default: auto) |
| `--trust-hyperscan` | Trust HyperScan results for Deep Scan (skip -p- check) |
| `--udp-mode` | `quick` (priority ports) or `full` (top ports) |
| `--redteam` | Add AD/Kerberos/SNMP recon techniques |
| `--redteam-active-l2` | Enable noisier L2 active probing |
| `--agentless-verify` | Enable agentless verification (SMB/RDP/LDAP/SSH/HTTP) |
| `--no-agentless-verify` | Disable agentless verification (overrides defaults) |
| `--agentless-verify-max-targets N` | Cap agentless verification targets (1-200, default: 20) |

### Authenticated Scanning (Phase 4)

| Flag | Description |
| :--- | :--- |
| `--auth-provider {env,keyring}` | Credential backend (default: keyring) |
| `--credentials-file PATH` | Load universal credentials list from JSON |
| `--generate-credentials-template` | Create template `credentials.json` and exit |
| `--ssh-user USER` | SSH Username |
| `--ssh-key PATH` | Private Key path |
| `--ssh-trust-keys` | Auto-accept unknown host keys (Caution!) |
| `--smb-user USER` | SMB/Windows Username |
| `--smb-pass PASS` | SMB Password (preferred via wizard/env) |
| `--smb-domain DOMAIN` | Windows Domain |
| `--snmp-user USER` | SNMPv3 Username |
| `--snmp-auth-proto {SHA,MD5...}` | SNMPv3 Auth Protocol |
| `--snmp-priv-proto {AES,DES...}` | SNMPv3 Privacy Protocol |
| `--lynis` | Enable Lynis hardening audit (requires SSH) |

### Reporting & Integration

| Flag | Description |
| :--- | :--- |
| `-o, --output DIR` | Custom output directory |
| `--lang` | Interface/report language (en/es) |
| `--html-report` | Generate interactive dashboard (HTML) |
| `--webhook URL` | Send webhook alerts (JSON) for high/critical findings |
| `--nuclei` | Enable Nuclei template scanning (requires `nuclei`; runs in full mode only; OFF by default) |
| `--nuclei-timeout S` | Nuclei batch timeout in seconds (default: 300) |
| `--no-nuclei` | Disable Nuclei template scanning (default) |
| `--no-vuln-scan` | Skip Nikto/Web vulnerability scanning |
| `--cve-lookup` | Correlate services with NVD CVE data |

Notes:

- Web app scanners (sqlmap/ZAP) are skipped on infrastructure UIs when identity evidence indicates router/switch/AP devices.
- Nuclei runs may be marked partial when batches time out; check `nuclei.partial`, `nuclei.timeout_batches`, and `nuclei.failed_batches` in reports.
- **Nuclei on web-dense networks:** On networks with many HTTP/HTTPS services (e.g., Docker labs, microservices), Nuclei scans may take significantly longer (30-90+ minutes). Use `--nuclei-timeout 600` to increase the batch timeout, or `--no-nuclei` to skip Nuclei entirely if speed is critical.

### Nuclei Configuration (v4.17+)

Nuclei scanning has two independent configuration options:

**1. Scan Profile (`--profile`)**

Controls which templates are executed:

| Profile | Description | Time Estimate |
|:--------|:------------|:--------------|
| `full` | All templates, all severity levels | ~2 hours |
| `balanced` | Core security templates (cve, default-login, exposure, misconfig) | ~1 hour (recommended) |
| `fast` | Critical CVEs only | ~30-60 minutes |

**2. Full Coverage (wizard only)**

During interactive mode, the wizard asks "Scan ALL detected HTTP ports?" This controls which HTTP ports are scanned per host:

| Option | Behavior |
|:-------|:---------|
| **No (default for balanced/fast)** | Max 2 URLs per multi-port host (prioritizes 80, 443) |
| **Yes (default for full)** | Scan ALL detected HTTP ports on every host (beyond 80/443) |

Note: This option is only available in the interactive wizard, not via CLI flags.
When full coverage is enabled, the auto-fast profile switch is skipped so the selected profile is honored.

**When to use each combination:**

| Scenario | Recommended Settings |
|:---------|:--------------------|
| Quick vulnerability check | `--profile fast` |
| Standard audit | `--profile balanced` (wizard: No to full coverage) |
| Thorough pentest | `--profile full` (wizard: Yes to full coverage) |
| Time-constrained audit | `--profile fast` |

**Performance notes:**

- Hosts with many HTTP ports (e.g., FRITZ!Box with 8+ ports) can dominate scan time.
- Audit-focus mode (default) significantly reduces scan time on multi-port hosts.
- Enable full coverage only when exhaustive HTTP scanning is required.

**Optional Performance Boost:**

Install [RustScan](https://github.com/RustScan/RustScan) for faster port discovery:

```bash
# Ubuntu/Debian
cargo install rustscan
```

RustScan is automatically detected and used for HyperScan when available.

### Installer Toolchain Policy

The installer can pin or use latest versions for GitHub-downloaded tools:

```bash
# Latest versions for testssl and kerbrute
REDAUDIT_TOOLCHAIN_MODE=latest sudo bash redaudit_install.sh

# Explicit version overrides
TESTSSL_VERSION=v3.2 KERBRUTE_VERSION=v1.0.3 RUSTSCAN_VERSION=2.3.0 sudo bash redaudit_install.sh
```

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
- **run_manifest.json**: Output manifest with config/pipeline snapshot (disabled by `--encrypt`).
- **.pcap**: Packet captures (only if Deep Scan + tcpdump + Root).
- **session_*.log**: Raw terminal output with color codes (in `session_logs/`).
- **session_*.txt**: Clean plain-text terminal output (in `session_logs/`).

**Evidence & pipeline transparency:**

- The main JSON includes per-finding evidence metadata (source tool, matched_at, raw output hash/ref when available).
- HTML shows the resolved Nmap args/timing, deep scan settings, and HyperScan vs final summary (when present).

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

**Hidden VLANs not detected (802.1Q)**
RedAudit discovers networks via routing tables (`ip route`) and ARP neighbors.
VLANs isolated at Layer 2 (e.g., ISP IPTV VLANs tagged by managed switches) are **not discoverable** from the audit host.
**Workarounds:**

- Query router/switch via SNMP (`--redteam` with SNMP enabled)
- Manually add known VLANs to target list
- For Cisco environments, use `--net-discovery` with CDP/LLDP if switches broadcast topology

---

[Back to README](../README.md) | [Documentation Index](INDEX.md)
