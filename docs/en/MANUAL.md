# RedAudit v3.5.0 – User Manual (EN)

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](../es/MANUAL.md)

**Version:** 3.5.0
**Target audience:** Security analysts, penetration testers, systems / network administrators
**License:** GPLv3

---

## Table of contents

1. [Introduction](#1-introduction)
2. [System requirements](#2-system-requirements)
3. [Installation](#3-installation)
   - 3.1 [Quick install](#31-quick-install)
   - 3.2 [What the installer does](#32-what-the-installer-does)
   - 3.3 [Manual installation / uninstall](#33-manual-installation--uninstall)
4. [Concepts & architecture](#4-concepts--architecture)
   - 4.1 [Goals](#41-goals)
   - 4.2 [High-level workflow](#42-high-level-workflow)
   - 4.3 [Scan modes](#43-scan-modes)
5. [CLI usage](#5-cli-usage)
   - 5.1 [Basic syntax](#51-basic-syntax)
   - 5.2 [Core options](#52-core-options)
   - 5.3 [Typical scenarios](#53-typical-scenarios)
6. [Reports & output](#6-reports--output)
   - 6.1 [Directory layout](#61-directory-layout)
   - 6.2 [JSON report structure](#62-json-report-structure)
   - 6.3 [Text (TXT) summary](#63-text-txt-summary)
7. [Encryption & decryption](#7-encryption--decryption)
8. [Security model](#8-security-model)
   - 8.1 [Input & command safety](#81-input--command-safety)
   - 8.2 [Privilege model](#82-privilege-model)
   - 8.3 [Operational security](#83-operational-security)
   - 8.4 [Ethical and legal use](#84-ethical-and-legal-use)
9. [External tools](#9-external-tools)
10. [Monitoring & troubleshooting](#10-monitoring--troubleshooting)
11. [Contributing & tests](#11-contributing--tests)
12. [License & legal notice](#12-license--legal-notice)

---

## 1. Introduction

RedAudit is an automated network auditing and hardening assistant for Kali / Debian-based systems. It guides the operator through a structured workflow:

- Discovery of live hosts.
- Service and port enumeration.
- Web and TLS fingerprinting when applicable.
- Optional deep analysis on "interesting" hosts.
- Generation of SIEM-friendly JSON reports and human-readable summaries, optionally encrypted.

RedAudit is not an exploit framework and does not perform automatic exploitation. Instead, it focuses on visibility, structure and safe reporting so that a human analyst can take informed decisions.

### Key features

- Single-command CLI for whole-network reconnaissance and audit.
- Three scan modes (fast, normal, full) with adaptive workflow.
- Automatic activation of external tools (nmap, whatweb, nikto, testssl.sh, etc.) when relevant.
- JSON report schema designed for ingestion into SIEM / reporting pipelines.
- Optional AES-based encryption of reports with proper key derivation.
- Rate-limiting and jitter to control scan noise.
- Persistent defaults stored in `~/.redaudit/config.json` (optional, for automation).
- Optional topology discovery (ARP/VLAN/LLDP + gateway/routes) for L2 context and "hidden network" hints.
- Optional enhanced network discovery (`--net-discovery`) with broadcast/L2 signals and an opt-in `redteam` recon block (best-effort).
- **Interactive HTML Dashboard** (`--html-report`): Self-contained visual report with charts and search. (v3.3)
- **Webhook Alerting** (`--webhook`): Real-time finding notifications to external services. (v3.3)
- **Remediation Playbooks**: Auto-generated Markdown playbooks per host/category in `<output_dir>/playbooks/`. (v3.4)
- Bilingual messages (English / Spanish).

---

## 2. System requirements

| Requirement   | Minimum / supported                                  |
|---------------|------------------------------------------------------|
| OS            | Kali Linux, Debian 11+, Ubuntu 20.04+, Parrot OS     |
| Python        | 3.9+ (system Python)                                 |
| Privileges    | sudo / root recommended (raw sockets, nmap, tcpdump) |
| Disk space    | ~50 MB for code and dependencies + space for reports |
| Network       | Local or routed reachability to targets              |

RedAudit is designed for Linux only. It is not intended to run natively on Windows or macOS.

Note: a limited non-root mode is available via `--allow-non-root`, but some scan features may fail or be skipped.

---

## 3. Installation

### 3.1 Quick install

```bash
# 1) Clone the repository
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit

# 2) Run the installer with sudo
sudo bash redaudit_install.sh
```

During installation you will be asked to select language (English/Spanish) and whether to install additional tools.

After installation, reload your shell configuration:

```bash
# Zsh (default on recent Kali versions)
source ~/.zshrc

# Bash
source ~/.bashrc
```

From this point, the `redaudit` command should be available in your terminal.

---

### 3.2 What the installer does

The script `redaudit_install.sh` performs the following steps:

1. **Environment checks**
   - Verifies that `apt` is available (Debian-family systems).
   - Verifies that you are running with sudo or as root.

2. **Core dependencies**
   Installs or validates packages such as (names may vary slightly by distribution):
   - `curl`, `wget`, `openssl`, `git`
   - `nmap`
   - `tcpdump`, `tshark`
   - `whois`, `bind9-dnsutils`
   - `python3-nmap`, `python3-cryptography`, `python3-netifaces`
   - `exploitdb` (for searchsploit)
   - `nbtscan`, `netdiscover`, `fping`, `avahi-utils` (for enhanced discovery)
   - `snmp`, `snmp-mibs-downloader`, `enum4linux`, `smbclient`, `samba-common-bin` (rpcclient), `masscan`, `ldap-utils`, `bettercap`, `python3-scapy`, `proxychains4` (for Red Team recon)
   - `kerbrute` (downloaded from GitHub)

3. **Code deployment**
   - Copies the Python package directory `redaudit/` into `/usr/local/lib/redaudit`.
   - Ensures executable permissions for scripts and modules.
   - Injects the chosen default language into `utils/constants.py`.

4. **CLI wrapper**
   - Installs the `redaudit` launcher script into a directory on your PATH (typically `/usr/local/bin`).
   - Configures a shell alias so that typing `redaudit` invokes the application.

5. **Optional extras**
   - Offers to install a recommended bundle of utilities in a single `apt install` command.

No system services or daemons are installed; RedAudit is a stateless CLI tool.

---

### 3.3 Manual installation / uninstall

If you prefer not to use the installer:

1. Clone the repository:

   ```bash
   git clone https://github.com/dorinbadea/RedAudit.git
   cd RedAudit
   ```

2. Install dependencies manually (example):

   ```bash
	   sudo apt update
	   sudo apt install curl wget openssl nmap tcpdump tshark \
	                    whois bind9-dnsutils python3-nmap \
	                    python3-cryptography python3-netifaces exploitdb git \
	                    nbtscan netdiscover fping avahi-utils arp-scan lldpd \
	                    snmp enum4linux smbclient samba-common-bin masscan ldap-utils bettercap python3-scapy proxychains4
	   ```

3. Install `kerbrute` (manual step):

   ```bash
   sudo wget -O /usr/local/bin/kerbrute https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
   sudo chmod +x /usr/local/bin/kerbrute
   ```

4. Run via Python module:

   ```bash
   sudo python3 -m redaudit
   ```

**To uninstall:**

- Remove `/usr/local/lib/redaudit` (or the directory where you installed it).
- Remove the `redaudit` script and any alias you added to `.bashrc` / `.zshrc`.
- Optionally remove the dependency packages if you installed them exclusively for RedAudit.

---

## 4. Concepts & architecture

### 4.1 Goals

RedAudit's design philosophy is:

- **Secure by default:** conservative timeouts, strict input validation, and encrypted reports when requested.
- **Deterministic and inspectable:** JSON output with clear schema; easy to transform or ingest.
- **Operator-driven:** assists the human analyst instead of replacing their judgment.

### 4.2 High-level workflow

At a high level, a run of RedAudit follows this sequence:

1. **Interactive Setup (Wizard)**
   - If running interactively, the user selects an action from the **Main Menu**.
   - Input of target ranges and selection of **Topology Mode** (Full, Standard, or Topology Only).

2. **Network Discovery (Optional, v3.2)**
   - If enabled (`--net-discovery` or via the interactive wizard), broadcasts probes via ARP, mDNS, NetBIOS, and DHCP to find hidden hosts.
   - Opt-in Red Team recon can be enabled (`--redteam` or wizard option B); active L2 probing requires `--redteam-active-l2`.
   - Kerberos user enumeration via Kerbrute runs only when explicitly enabled and a userlist is provided (authorized testing only).

3. **Discovery**
   - Uses `nmap -sn` (host discovery) to find live hosts in the target range.

4. **Topology discovery (Optional, v3.1+)**
   - Best-effort gateway/routes mapping plus L2 hints (ARP/VLAN/LLDP) when tools and privileges are available.

5. **Port & service scan**
   - Uses `nmap -sV` (service/version detection) on discovered hosts.
   - For `full` mode, scans a wider port range and additional scripts.

6. **Conditional web & TLS analysis**
   - If HTTP/HTTPS ports are found:
     - `whatweb` fingerprints technologies.
     - `curl` / `wget` fetch headers.
     - In `full` mode, `nikto` and `testssl.sh` are invoked for deeper checks.

7. **Deep scan / identity refinement (triggered selectively)**
   - If a host is ambiguous or "interesting" (few ports, strange services, incomplete fingerprint), a deeper scan is run:
     - Additional `nmap` probes, optional packet capture with `tcpdump`, optional summarisation with `tshark`.

8. **Post-processing & reporting**
   - Consolidates all collected data into a structured JSON report.
   - Generates a TXT summary report (if enabled).
   - Generates remediation playbooks as Markdown in `<output_dir>/playbooks/`.
   - Generates an interactive HTML Dashboard (`--html-report`).
   - Exports JSONL artifacts for SIEM/AI pipelines (when encryption is disabled).
   - Optionally encrypts report files using `cryptography` (Fernet).

> **Encryption note**: When report encryption is enabled, RedAudit writes encrypted JSON/TXT artifacts (plus a `.salt` file) and skips plaintext artifacts (HTML/JSONL/playbooks).

The control logic for this pipeline lives mainly in the package `redaudit/core`.

---

### 4.3 Scan modes

RedAudit exposes three scan modes. The CLI mode names are in English and must be passed as such (`fast`, `normal`, `full`), regardless of interface language.

| Mode   | CLI value | Description                                             | Typical use case                        |
|--------|-----------|--------------------------------------------------------|----------------------------------------|
| Fast   | `fast`    | Host discovery only (`nmap -sn`).                       | Quick inventory; verify reachability.  |
| Normal | `normal`  | Top ports + service versions.                           | Standard security audit of a network.  |
| Full   | `full`    | Extended ports + scripts + web/TLS + **net discovery** (v3.2.1). | Comprehensive audit / pre-pentest review. |

Changing the mode affects how aggressively external tools are invoked and how many ports/probes are used.

---

## 5. CLI usage

### 5.1 Basic syntax

You can run RedAudit either interactively (no arguments) or non-interactively.

```bash
# Interactive mode (launches the Main Menu)
sudo redaudit
```

When launched without arguments, RedAudit presents an **Interactive Main Menu**:

1. **Start Network Scan**: Enters the guided wizard for scanning.
2. **Check for Updates**: Runs the interactive updater (requires `sudo`).
3. **Diff Two Reports**: Compares 2 JSON reports to show changes.
0. **Exit**: Quits the application.

After a successful update, RedAudit displays a "restart the terminal" notice and exits to ensure a clean load of the new version.

If you choose to scan, you will be guided through:

- Target selection (IP/CIDR).
- **Topology Mode**: Choose between Full Scan (+Topology), Standard (No Topology), or Topology Only.
- Scan Mode (Fast, Normal, Full).
- Additional options (Encryption, Defaults).

#### Interactive vs Non-Interactive Modes

| Aspect | Interactive Mode | Non-Interactive Mode |
|--------|------------------|----------------------|
| **Launch** | `sudo redaudit` | `sudo redaudit --target X --yes` |
| **Configuration** | Guided wizard prompts | All via CLI flags |
| **Main Menu** | Yes (Scan / Update / Diff / Exit) | No (direct execution) |
| **Defaults** | Prompted to use/save | Must specify `--use-defaults` or `--ignore-defaults` |
| **Use Case** | Manual audits, exploration | Automation, scripts, CI/CD |
| **Update Check** | Prompted at startup | Skipped (use `--skip-update-check` explicit) |

### Non-interactive mode (automation)

```bash
sudo redaudit --target 192.168.1.0/24 --mode normal --yes
```

The module can also be invoked directly:

```bash
sudo python3 -m redaudit [OPTIONS]
```

---

### 5.2 Core options

The full list is available via:

```bash
redaudit --help
```

The most important options:

| Option                      | Description                                                                                                              |
|-----------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `-t`, `--target CIDR`       | Target network(s) in CIDR notation. Comma-separated for multiple ranges.                                                 |
| `-m`, `--mode {fast,normal,full}` | Select scan mode (see above). Default: `normal`.                                                                   |
| `-j`, `--threads N`         | Concurrent scanning threads. Range constrained by built-in safe defaults.                                               |
| `--max-hosts N`             | Maximum number of discovered hosts to scan. Default: all. *(This is a cap, not a host selector.)*                         |
| `--rate-limit SECONDS`      | Delay between host scans to reduce noise on the wire. Default: 0.                                                        |
| `--dry-run`                 | Print commands that would be executed without running them (no external commands are executed). **(v3.5+)**               |
| `--no-prevent-sleep`        | Do not inhibit system/display sleep while a scan is running. **(v3.5)**                                                   |
| `-e`, `--encrypt`           | Enable encryption of generated reports.                                                                                  |
| `--encrypt-password PASS`   | Password for encryption in non-interactive runs. If omitted with `--encrypt`, you'll be prompted or a random password may be generated and printed. |
| `--no-vuln-scan`            | Disable web vulnerability scanning (skip nikto / certain HTTP checks).                                                   |
| `--no-txt-report`           | Skip generation of the human-readable TXT report.                                                                       |
| `-o`, `--output DIR`        | Base output directory for reports. Default: `~/Documents/RedAuditReports` (invoking user under `sudo`; a timestamped `RedAudit_...` folder is created). |
| `--yes`                     | Non-interactive mode: assume "yes" to prompts. Essential for automation.                                                 |
| `--prescan`                 | Enable asynchronous pre-scan to reduce nmap calls on very large ranges.                                           |
| `--prescan-ports`           | Port range for pre-scan (e.g., `1-1000` or `top-1000`). Default: `1-1024`.                                               |
| `--prescan-timeout`         | Timeout per port in seconds for pre-scan. Default: `0.5`.                                                                |
| `--udp-mode {quick,full}`   | UDP deep-scan mode: `quick` (priority ports) or `full` (top UDP ports for identity discovery). Default: `quick`.   |
| `--udp-ports N`             | Top UDP ports count used in `--udp-mode full` (range: 50-500). Default: 100. **(v3.1+)**                            |
| `--topology`                | Enable topology discovery (ARP/VLAN/LLDP + gateway/routes). **(v3.1+)**                                               |
| `--no-topology`             | Disable topology discovery (override persisted defaults). **(v3.1+)**                                                 |
| `--topology-only`           | Run topology discovery only (skip host scanning). **(v3.1+)**                                                         |
| `--save-defaults`           | Save current CLI settings as persistent defaults (`~/.redaudit/config.json`). **(v3.1+)**                             |
| `--net-discovery [PROTO,...]` | Enable enhanced network discovery (all, or comma-separated: dhcp,netbios,mdns,upnp,arp,fping). **(v3.2+)**       |
| `--redteam`                 | Include opt-in Red Team recon block for net discovery (best-effort, slower/noisier). **(v3.2+)**                      |
| `--net-discovery-interface IFACE` | Interface for net discovery and L2 captures (e.g., eth0). **(v3.2+)**                                           |
| `--redteam-max-targets N`   | Max target IPs sampled for redteam checks (1-500, default: 50). **(v3.2+)**                                           |
| `--snmp-community COMMUNITY` | SNMP community for SNMP walking (default: public). **(v3.2+)**                                                       |
| `--dns-zone ZONE`           | DNS zone hint for AXFR attempt (e.g., corp.local). **(v3.2+)**                                                        |
| `--kerberos-realm REALM`    | Kerberos realm hint (e.g., CORP.LOCAL). **(v3.2+)**                                                                   |
| `--kerberos-userlist PATH`  | Optional userlist for Kerberos userenum (requires kerbrute; use only with authorization). **(v3.2+)**                 |
| `--redteam-active-l2`       | Enable additional L2-focused checks that may be noisier (bettercap/scapy sniff; requires root). **(v3.2+)**           |
| `--skip-update-check`       | Skip the update check prompt at startup.                                                                          |
| `--ipv6`                    | Enable IPv6-only scanning mode. **(v3.0)**                                                                        |
| `--proxy URL`               | SOCKS5 proxy for pivoting (e.g., `socks5://host:1080`). **(v3.0)**                                                |
| `--diff OLD NEW`            | Compare two JSON reports and generate delta analysis. **(v3.0)**                                                  |
| `--cve-lookup`              | Enable CVE correlation via NVD API. **(v3.0)**                                                                    |
| `--nvd-key KEY`             | NVD API key for faster rate limits (optional). **(v3.0)**                                                         |
| `--html-report`             | Generate interactive HTML dashboard. **(v3.3)**                                                                   |
| `--webhook URL`             | POST findings to this URL (e.g., Slack/Teams webhook). **(v3.3)**                                                 |
| `-V`, `--version`           | Print RedAudit version and exit.                                                                                         |

Persistent defaults: if `--save-defaults` is used, RedAudit stores settings under `defaults` in `~/.redaudit/config.json` and reuses them as defaults in future runs.

Interactive note: when asked for “Maximum number of hosts to scan”, press ENTER to scan all discovered hosts, or type a number to apply a global limit.

For more usage examples, see [USAGE.md](USAGE.md).

---

### 5.3 Typical scenarios

**1. Quick LAN inventory (fast discovery)**

```bash
sudo redaudit --target 192.168.1.0/24 --mode fast --yes
```

**2. Standard audit with encryption**

```bash
sudo redaudit \
  --target 10.0.0.0/24 \
  --mode normal \
  --encrypt \
  --encrypt-password "StrongPassw0rd!" \
  --yes
```

**3. Comprehensive audit for a small subnet**

```bash
sudo redaudit \
  --target 172.16.10.0/28 \
  --mode full \
  --threads 4 \
  --rate-limit 2 \
  --prescan \
  --yes
```

**4. Enhanced network discovery (v3.2)**

```bash
# Broadcast discovery only
sudo redaudit --target 192.168.1.0/24 --net-discovery --yes

# With opt-in redteam recon (best-effort)
sudo redaudit --target 192.168.1.0/24 --net-discovery --redteam --net-discovery-interface eth0 --yes
```

---

## 6. Reports & output

### 6.1 Directory layout

After a run, RedAudit creates a timestamped output directory (v2.8+) such as:

```text
~/Documents/RedAuditReports/
└── RedAudit_2025-01-15_21-30-45/
    ├── redaudit_20250115_213045.json
    ├── redaudit_20250115_213045.txt
    ├── report.html                   # v3.3 Interactive Dashboard (fixed name)
    ├── findings.jsonl                # Flat findings export (SIEM/AI)
    ├── assets.jsonl                  # Flat assets export (SIEM/AI)
    ├── summary.json                  # Compact dashboard summary
    ├── run_manifest.json             # Output folder manifest (files + counts)
    ├── playbooks/                    # Remediation playbooks (Markdown)
    └── traffic_192_168_1_*.pcap      # Optional packet captures
```

Each scan session gets its own subfolder for organization.

If encryption is enabled, the JSON and TXT files will instead use `.enc` suffixes and have associated `.salt` files.
For safety, plaintext artifacts (HTML/JSONL/playbooks/manifests) are generated only when encryption is disabled.

---

### 6.2 JSON report structure

The JSON schema is described in detail in [REPORT_SCHEMA.md](REPORT_SCHEMA.md). At a high level:

- **Root object**
  - Metadata: tool version, start/end times, operator options, exit status.
  - Target information: ranges, resolved hostnames if available.
  - Optional topology block (`topology`) when topology discovery is enabled.

- **hosts[]**
  - One object per discovered host:
    - `ip`, `hostname`, `os_guess`, `mac_address`
    - `ports[]` with:
      - `port`, `protocol`, `state`, `service`, `product`, `version`
      - `known_exploits[]` (results from searchsploit)
    - `dns` (reverse lookups, additional records)
    - `whois_summary` (for public IPs).

- **vulnerabilities[]**
  - Per-host / per-service findings:
    - `whatweb` fingerprints.
    - `nikto_findings` (if run).
    - `curl_headers`, `wget_headers`.
    - `tls_info` and `testssl_analysis` for HTTPS ports.

- **deep_scan (optional)**
  - Appears only when the deep scan subsystem was triggered:
    - Additional fingerprints.
    - `pcap_capture` metadata, and optional `tshark_summary`.

The schema is stable and versioned to ease integration with SIEM, dashboards, or custom scripts.

#### 6.2.1 SIEM Integration (v3.1)

When encryption is disabled, RedAudit generates flat-file exports optimized for SIEM/AI ingestion:

**findings.jsonl** - One vulnerability per line:

```json
{"finding_id":"...","asset_ip":"192.168.1.10","port":80,"url":"http://192.168.1.10/","severity":"low","normalized_severity":1.0,"category":"surface","title":"Missing HTTP Strict Transport Security Header","timestamp":"...","session_id":"...","schema_version":"...","scanner":"RedAudit","scanner_version":"..."}
```

**assets.jsonl** - One host per line:

```json
{"asset_id":"...","ip":"192.168.1.10","hostname":"webserver.local","status":"up","risk_score":62,"total_ports":3,"web_ports":1,"finding_count":7,"tags":["web"],"timestamp":"...","session_id":"...","schema_version":"...","scanner":"RedAudit","scanner_version":"..."}
```

**summary.json** - Dashboard-ready metrics:

```json
{"schema_version":"...","generated_at":"...","session_id":"...","scan_duration":"0:05:42","total_assets":15,"total_findings":47,"severity_breakdown":{"critical":2,"high":8,"medium":21,"low":16,"info":0},"targets":["..."],"scanner_versions":{"redaudit":"..."},"redaudit_version":"..."}
```

**run_manifest.json** - Folder manifest with counts and file list:

```json
{"session_id":"...","redaudit_version":"...","counts":{"hosts":15,"findings":47,"pcaps":3},"artifacts":[{"path":"report.html","size_bytes":12345}]}
```

**Ingestion examples:**

```bash
# Elasticsearch
cat findings.jsonl | curl -X POST "localhost:9200/redaudit-findings/_bulk" \
  -H 'Content-Type: application/x-ndjson' --data-binary @-

# Splunk HEC
cat findings.jsonl | while read line; do
  curl -k "https://splunk:8088/services/collector" \
    -H "Authorization: Splunk YOUR_TOKEN" -d "{\"event\":$line}"
done

# Custom processing
jq -r 'select(.normalized_severity >= 7.0) | "\(.asset_ip) - \(.title)"' findings.jsonl
```

---

### 6.3 Text (TXT) summary

The TXT summary file is a human-oriented overview:

- High-level description of the run (targets, mode, duration).
- Inventory of hosts with a compact list of open ports.
- Highlights of potential issues (e.g. outdated services, HTTP findings).

Use the JSON for automation and the summary for manual review or to include in reports.

---

## 7. Encryption & decryption

When `--encrypt` is used, RedAudit leverages the Python `cryptography` library (Fernet) to protect report contents.

### Encryption model

- Symmetric encryption using AES-128-CBC + HMAC-SHA256, as per Fernet specification.
- Keys derived from the password via PBKDF2-HMAC-SHA256 with a high iteration count and a per-session random salt.
- Ciphertext includes a signature to detect tampering.

**Password policy (enforced by the tool):**

- Minimum length 12 characters.
- Mixed character classes (upper/lower/digit recommended for strength).

### Decrypting reports

Use `redaudit_decrypt.py`:

```bash
# Decrypt an encrypted JSON report (you will be prompted for the password)
python3 redaudit_decrypt.py /path/to/redaudit_20250115_213045.json.enc
```

The helper script:

1. Locates the corresponding `.salt` file (based on naming conventions).
2. Derives the encryption key.
3. Verifies integrity and decrypts the content.
4. Writes the decrypted file next to the encrypted one (same name without `.enc`, unless you choose a different name when prompted).

If you lose the password, the reports cannot be recovered. There is no backdoor or password reset mechanism.

For more details on the security model, see [SECURITY.md](SECURITY.md).

---

## 8. Security model

For comprehensive security documentation, refer to [SECURITY.md](SECURITY.md).

### 8.1 Input & command safety

All external inputs are treated as untrusted:

- Target ranges, hostnames, and similar fields are strictly validated (type checks and allowlisting regex).
- The tool assembles commands using `subprocess.run` with argument lists, never `shell=True`.
- User-supplied strings are never interpolated directly into shell commands.

This mitigates:

- Shell injection.
- Accidental execution of arbitrary code via malicious input.

---

### 8.2 Privilege model

- RedAudit requires `sudo` primarily for raw socket operations performed by `nmap` and optional packet capture (`tcpdump`).
- It does not install privileged daemons or keep background services running.
- Temporary files and report artifacts are created with restrictive permissions (e.g. `0o600`) to prevent disclosure to other local users.

**Best practice:** only trusted administrators should run RedAudit on production systems.

---

### 8.3 Operational security

To reduce scan noise and side effects:

- **Rate limiting & jitter:** you can slow down the host scanning loop and introduce variability in request timing to avoid IDS thresholds.
- **Bounded captures:** packet capture durations are tightly restricted to prevent long-running sniffs.
- **Timeouts & retries:** subprocesses and network operations include reasonable timeouts and retry caps to avoid hanging processes.

RedAudit is designed to fail clearly rather than silently.

---

### 8.4 Ethical and legal use

RedAudit is a powerful scanning tool. Use it responsibly:

- Only run it against networks and hosts for which you have explicit permission.
- Respect organisational policies, maintenance windows, and legal constraints.
- Do not rely solely on automated output; human review is required before taking action.

The author and contributors assume no responsibility for misuse.

---

## 9. External tools

RedAudit orchestrates multiple third-party tools. The following list is not exhaustive but covers the main ones:

| Tool         | Trigger condition                        | Mode(s)              | Where it appears in reports              |
|--------------|------------------------------------------|----------------------|------------------------------------------|
| `nmap`       | Always                                   | All                  | `host.ports[]`                           |
| `searchsploit` | Service with version detected          | All                  | `ports[].known_exploits[]`               |
| `whatweb`    | HTTP/HTTPS port detected                 | All                  | `vulnerabilities[].whatweb`              |
| `nikto`      | HTTP/HTTPS port detected                 | `full`               | `vulnerabilities[].nikto_findings`       |
| `curl`       | HTTP/HTTPS port detected                 | All                  | `vulnerabilities[].curl_headers`         |
| `wget`       | HTTP/HTTPS port detected                 | All                  | `vulnerabilities[].wget_headers`         |
| `openssl`    | HTTPS port detected                      | All                  | `vulnerabilities[].tls_info`             |
| `testssl.sh` | HTTPS port detected                      | `full`               | `vulnerabilities[].testssl_analysis`     |
| `tcpdump`    | Deep scan enabled (PCAP) or `--redteam` L2 capture | All (if triggered) | `deep_scan.pcap_capture` / `net_discovery.redteam.*` |
| `tshark`     | After tcpdump capture                    | All (if triggered)   | `deep_scan.pcap_capture.tshark_summary`  |
| `dig` / `host` | After port scan                        | All                  | `host.dns`                               |
| `whois`      | Public IPs only                          | All                  | `host.dns.whois_summary`                 |
| `fping`      | `--net-discovery` enabled                | All                  | `net_discovery.alive_hosts`              |
| `nbtscan`    | `--net-discovery netbios` enabled        | All                  | `net_discovery.netbios_hosts`            |
| `netdiscover` | `--net-discovery arp` enabled           | All                  | `net_discovery.arp_hosts`                |
| `avahi-browse` | `--net-discovery mdns` enabled          | All                  | `net_discovery.mdns_services`            |
| `snmpwalk`   | `--redteam` enabled                      | All                  | `net_discovery.redteam.snmp`             |
| `enum4linux` | `--redteam` enabled (SMB)                | All                  | `net_discovery.redteam.smb`              |
| `rpcclient`  | `--redteam` enabled (RPC)                | All                  | `net_discovery.redteam.rpc`              |
| `ldapsearch` | `--redteam` enabled (LDAP)               | All                  | `net_discovery.redteam.ldap`             |
| `kerbrute`   | `--redteam` enabled (Kerberos; userlist) | All                  | `net_discovery.redteam.kerberos.userenum` |
| `masscan`    | `--redteam` enabled (optional)           | All                  | `net_discovery.redteam.masscan`          |

RedAudit does not modify the configuration of these tools; it calls them with explicit arguments and parses their output.

---

### 6.4. Potential Hidden Networks (Leak Detection)

*Added in v3.2.1*

RedAudit automatically analyzes HTTP headers (`Location`, `Content-Security-Policy`) and redirect chains to identify internal IP addresses that likely belong to other subnets (e.g., Guest Networks, Admin VLANs).

**Example Output**:

```text
⚠️  POTENTIAL HIDDEN NETWORKS (LEAKS DETECTED):
   (Professional Pivot / Discovery Tip: These networks are referenced in headers/redirects but were not scanned)
   - Host 192.168.178.1 leaks internal IP 192.168.189.1 (Potential Network: 192.168.189.0/24)
```

**What to do**:

- This indicates a **Pivoting Opportunity**. The target host can reach a network you cannot see.
- Investigate if you can route traffic to that subnet or if the host is dual-homed.

## 10. Monitoring & troubleshooting

### Monitoring

During execution, RedAudit provides:

- A heartbeat that periodically prints progress (e.g. "scanning host X of Y").
- Clear status messages for each phase: discovery, port scan, web/TLS analysis, deep scan, report generation.

For long runs, you can leave the terminal attached and simply monitor the heartbeat to ensure the process is advancing.

### Common issues (summary)

1. **"Permission denied" / root required**
   - **Cause:** command run without `sudo` (full mode requires raw socket operations).
   - **Fix:** prepend `sudo` and ensure your user is in sudoers, or use `--allow-non-root` for limited mode.

2. **"Command not found" for nmap, whatweb, etc.**
   - **Cause:** missing dependencies (installer skipped or failed).
   - **Fix:** re-run `redaudit_install.sh` or install the missing package with `apt`.

3. **"Decryption failed: Invalid token"**
   - **Cause:** wrong password for encrypted report.
   - **Fix:** verify the password; check that `.salt` file is present and not corrupted.

4. **Scans appear to "hang"**
   - **Cause:** deep scan on complex host; nmap plus fingerprinting can legitimately take minutes.
   - **Fix:** monitor heartbeat; if needed, reduce scope, lower concurrency, or use `fast`/`normal` mode.

5. **Alias not found after installation**
   - **Cause:** shell configuration not reloaded or installer was not run under the intended user.
   - **Fix:** run `source ~/.bashrc` or `source ~/.zshrc`. Ensure you executed the installer with `sudo` from the target user account.

For a more detailed list and specific exit codes, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## 11. Contributing & tests

RedAudit includes a pytest suite and a verification script.

- **Run unit tests:**

  ```bash
  cd /path/to/RedAudit
  pytest
  ```

- **Run the verification helper (sanity checks):**

  ```bash
  bash redaudit_verify.sh
  ```

Contributions should:

- Preserve the security model (no `shell=True`, no arbitrary code evaluation).
- Keep the report schema backward compatible whenever possible.
- Include tests for new features and changes.

Refer to [CONTRIBUTING.md](../../.github/CONTRIBUTING.md) for detailed guidelines.

---

## 12. License & legal notice

RedAudit is released under the **GNU General Public License v3.0**:

- You may run, study, modify, and redistribute the software under the conditions of GPLv3.
- Any derivative work that you distribute must also be licensed under GPLv3 and make its source code available.

The software is provided "as is", without any warranty of any kind, express or implied, including but not limited to fitness for a particular purpose or non-infringement.

Using RedAudit against systems without authorisation may be illegal in your jurisdiction. The author declines all responsibility for misuse.

---

**Related documentation:**

- [README (English)](../../README.md)
- [README (Spanish)](../../README_ES.md)
- [USAGE.md](USAGE.md) - Detailed usage examples
- [SECURITY.md](SECURITY.md) - Security model details
- [REPORT_SCHEMA.md](REPORT_SCHEMA.md) - JSON report schema
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Problem resolution
- [CONTRIBUTING.md](../../.github/CONTRIBUTING.md) - Contribution guidelines
- [CHANGELOG.md](../../CHANGELOG.md) - Version history
