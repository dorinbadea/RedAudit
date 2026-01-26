# RedAudit User Manual

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](MANUAL.es.md)

**Audience:** Security analysts, penetration testers, and system administrators.

**Scope:** Installation, operation, output artifacts, and security model.

**What this document does NOT cover:** Exploitation techniques and code internals.

**Source of Truth:** `redaudit --help`, `redaudit/core/auditor.py`

---

## 1. What RedAudit Is (and Is Not)

RedAudit is an **automated network auditing framework** for Linux (Debian-family). It orchestrates a comprehensive toolchain (`nmap`, `nikto`, `nuclei`, `whatweb`, `testssl.sh`, `sqlmap`, `rustscan`, and more) into a unified pipeline and produces structured reports.

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
cd RedAudit && sudo bash redaudit_install.sh
```

The installer:

1. Installs system dependencies via `apt`
2. Copies code to `/usr/local/lib/redaudit`
3. Creates the `redaudit` shell alias
4. Prompts for language preference (EN/ES)

Toolchain version policy (optional):

```bash
# Use latest versions for GitHub-downloaded tools (testssl, kerbrute)
REDAUDIT_TOOLCHAIN_MODE=latest sudo bash redaudit_install.sh

# Or pin specific tool versions explicitly
TESTSSL_VERSION=v3.2 KERBRUTE_VERSION=v1.0.3 RUSTSCAN_VERSION=2.3.0 sudo bash redaudit_install.sh
```

### Manual Install (without installer)

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo apt install nmap whatweb nikto tcpdump tshark exploitdb python3-nmap python3-cryptography
sudo python3 -m redaudit --help
```

### Developer / Reproducible Install (via pip)

For exact dependency matching (Phase 5 compliance), use a virtual environment:

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.lock
pip install .
```

Poetry users can rely on `poetry.lock` for evaluation; pip-tools remains the source of truth for lockfiles.

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
If you keep a local `~/RedAudit` git checkout, system updates refresh that home copy so documentation stays current. When local changes are detected, the updater backs up the folder with a timestamped suffix before updating; clean `main` repos may be fast-forwarded, while dirty or non-`main` branches are left untouched.

---

## 4. Comprehensive Wizard Guide

The interactive wizard is the recommended way to use RedAudit. It guides you step-by-step to configure the perfect scan for your needs.

### Workflow

1. **Startup & Updates:** Upon running `sudo redaudit`, the tool automatically checks for new versions (unless `--skip-update-check` is used).
2. **Profile Selection:** Choose a preset or configure manually.
3. **Target Selection:** Choose detected networks or enter manual targets; the wizard shows normalized targets with estimated host counts.
4. **Authentication Setup:** (New in v4.0) Configure SSH/SMB/SNMP credentials for deep audits.
5. **Confirmation:** Review the summary before starting.

### Scan Profiles

Pre-configured profiles adjust dozens of parameters automatically:

#### 1. Express (Fast / Inventory)

**Goal:** Get a list of live hosts and their vendors in seconds.

- **Technique:** Ping Sweep (ICMP/ARP), no port scanning.
- **Ideal for:** Initial asset inventory, connectivity checks.
- **Estimated time:** < 30s for /24.

#### 2. Standard (Balanced / General Audit)

**Goal:** Identify common services and obvious vulnerabilities.

- **Technique:** Top 100 TCP ports (`-F`), version and OS detection.
- **Web:** Checks headers and basic technologies (WhatWeb).
- **Authentication:** Optional setup for SSH/SMB/SNMP credentials.
- **Ideal for:** Regular audits, policy validation.

#### 3. Exhaustive (Deep / Compliance)

**Goal:** Find EVERYTHING.

- **Technique:** 65535 TCP ports, UDP scanning, vulnerability scripts (NSE).
- **Web:** Full scan (Nikto, Nuclei, SSL).
- **Authentication:** Optional setup for SSH/SMB/SNMP credentials.
- **Ideal for:** Penetration testing, compliance (PCI-DSS, ISO 27001), pre-production validation.

#### 4. Custom (Tailored)

**Goal:** Full control.

- **Allows configuring:**
  - **Nmap Mode:** Fast/Normal/Full.
  - **Timing:** Stealth/Normal/Aggressive.
  - **Performance:** Threads (1-100) and Rate Limit (seconds between requests).
  - **Topology & Discovery:** Enable/disable L2 mapping and discovery protocols (mDNS, UPnP, etc.).
  - **UDP:** Enable UDP scanning (slow but thorough).
  - **Authentication:** Configure credentials for authenticated scanning.
  - **Agentless Verification:** Enable/disable lightweight checks.
  - **Web & Vulnerabilities:** Enable/disable Nikto, Nuclei, CVE lookup.

### Authentication Menu (Phase 4)

If you select **Standard**, **Exhaustive**, or **Custom** profiles, the wizard will ask:
`Enable authenticated scanning (SSH/SMB)? [y/n]`

If you answer **Yes**, you will enter the credentials sub-menu:

1. **SSH (Linux/Unix):**
    - User and Password OR Private Key.
    - Enables packet audit, hardening (Lynis), and internal configurations.
2. **SMB (Windows):**
    - User, Password, and Domain (optional).
    - Enables enumeration of users, shares, and password policies.
3. **SNMP v3 (Network):**
    - User, Auth Protocols (MD5/SHA), and Privacy (DES/AES).
    - Enables extraction of routing tables and network device configurations.

**Note:** Credentials can be securely saved to the system Keyring for future use.

### Scenario Examples (Tutorial)

#### Scenario A: Quick Inventory Audit

1. Run `sudo redaudit`.
2. Select **Express**.
3. Enter the client IP range (e.g., `192.168.10.0/24`).
4. Result: In minutes, you'll have an `assets.jsonl` with all live devices and vendors.

#### Scenario B: Linux Server Hardening Audit

1. Run `sudo redaudit`.
2. Select **Custom**.
3. Mode: **Normal**.
4. Authentication enabled: **Yes**.
    - Configure `root` user (or sudoer) and SSH key.
5. Enable Lynis: **Yes** (if asked or via `--lynis` flag).
6. Result: The report will include the Lynis "Hardening Index" and internal server details.

#### Scenario C: Red Team / Stealth

1. Run `sudo redaudit`.
2. Select **Custom**.
3. Mode: **Stealth** (reduces speed, avoids simple IDS detection).
4. Topology: **Passive** (listen only, no aggressive ARP).
5. Result: Network mapping with minimal noise footprint.

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

**Guidance (benefits/risks):**

- **fast**: Lowest noise and fastest. Best for inventory-only sweeps or fragile environments; no service detail.
- **normal**: Balanced time vs. coverage. Recommended default for most LAN audits.
- **full**: Maximum coverage and deeper identity work. Longest runtime and highest noise; may stress fragile devices.

**Timeout behavior:** Host scans are bounded by the nmap `--host-timeout` for the selected mode (full: 300s). RedAudit
enforces a hard timeout and marks the host as no-response if it is exceeded, keeping scans responsive on IoT/embedded
devices.

### Timing Presets (Wizard)

Timing controls how aggressively RedAudit schedules work (nmap timing + thread behavior).

- **Stealth**: Slowest, lowest noise. Best for detection-sensitive networks.
- **Normal**: Balanced speed and reliability. Good default for most networks.
- **Aggressive**: Fastest and noisiest. Can miss slow/filtered services and may increase false negatives on noisy links.

### Adaptive Deep Scan

When enabled (default), RedAudit performs additional scanning on hosts where initial results are ambiguous or indicate virtual infrastructure:

**Trigger conditions:**

- Fewer than 3 open ports found (when identity is weak)
- Services identified as `unknown` or `tcpwrapped`
- MAC/vendor information not obtained
- No version info and no strong identity evidence (HTTP title/server or device-type hints)
- **VPN Gateway Detection**: Host shares the MAC address with the gateway but has a different IP (virtual interface)

**Behavior:**

0. (Optional) Phase 0 low-impact enrichment (DNS reverse, mDNS unicast, SNMP sysDescr, and a short HTTP/HTTPS probe for vendor-only hosts with zero open ports) when enabled via the wizard prompt or `--low-impact-enrichment`
1. Phase 1: Aggressive TCP (`-A -p- -sV -Pn`)
2. Phase 2a: Priority UDP probe (17 common ports including 500/4500)
3. Phase 2b: UDP top-ports (`--udp-ports`) when mode is `full` and identity is still weak
4. When Phase 0 is enabled, quiet hosts with vendor hints and zero open ports may get a short HTTP/HTTPS probe on common paths to resolve identity early

Disable with `--no-deep-scan`.

SmartScan uses an identity score (default threshold: 3; full mode uses 4) to decide whether to escalate.

### Smart-Throttle (Adaptive Congestion Control)

RedAudit v4.4+ introduces:

- **Smart-Check Technology**: Correlates open ports (Nmap) with vulnerabilities (Nuclei) to eliminate false positives.
- **Parallel Discovery (v4.6.32)**: Executed DHCP, ARP, mDNS, UPnP, and Fping simultaneously for ultra-fast network mapping.
- **DHCP Discovery Interface**: Defaults to the system's default-route interface; in `full` mode it probes all active IPv4 interfaces with a short timeout.
- **HyperScan**: Uses asynchronous TCP/SYN packets to scan 65,535 ports in seconds (RustScan integration).
- **Smart-Throttle**: An adaptive rate limiting system for HyperScan operations.
- **Algorithm**: Uses an Additive Increase, Multiplicative Decrease (AIMD) algorithm similar to TCP congestion control.
- **Behavior**:
  - Starts with a conservative batch size (500 packets).
  - **Accelerates** (Linearly) when the network is stable (timeouts < 1%).
  - **Throttles** (Multiplicatively) when congestion is detected (timeouts > 5%).
- **Benefit**: Prevents packet loss on SOHO/VPN networks while maximizing speed on Data Center links (scaling up to 20,000 pps).
- **Feedback**: Real-time scan speed and throttling events (▼/▲) are displayed in the progress bar.
- **Progress Output**: When HyperScan runs with a Rich progress bar, per-host status lines are suppressed to avoid mixed UI. The bar itself shows per-IP detail.

VPN classification is handled by asset typing heuristics (gateway MAC/IP, VPN ports, hostname patterns) after scanning.

**Parallel Execution:**
Starting with v4.6, deep scans run in a dedicated thread pool (up to 100 threads), decoupled from the main discovery loop. This ensures that slow deep scans do not block the overall progress.

### Web Application Security (v4.2+)

RedAudit now integrates specialized tools for deep web application assessment:

- **sqlmap**: Automatically tests for SQL injection flaws on suspect parameters. Configurable via Custom Profile (Levels 1-5, Risks 1-3).
- **OWASP ZAP**: Optional DAST scanning for spidering and active scanning. Enabled via Custom Profile or config.
  - Both tools are skipped on infrastructure devices when identity evidence indicates router/switch/AP class hosts.

### Nuclei Partial Runs

When Nuclei batch scans time out, the run is marked as partial and the report includes timeout and failed batch indexes.
During long batches, the CLI shows time-based progress inside the batch (with elapsed time) so operators can confirm activity.
When a timeout occurs, RedAudit splits the batch and keeps the configured `--nuclei-timeout` as a floor for retries to avoid
dropping coverage on slow targets.

### Nuclei Runtime Budget and Resume

If you set a Nuclei runtime budget (wizard or `--nuclei-max-runtime`), Nuclei stops once the budget is reached and creates
`nuclei_resume.json` plus `nuclei_pending.txt` in the scan folder. You will be prompted to resume immediately with a
15-second countdown; if you do nothing, the scan continues and the resume remains available.

You can resume later from the main menu (**Resume Nuclei (pending)**) or from the CLI:

```bash
redaudit --nuclei-resume /path/to/scan/folder
redaudit --nuclei-resume /path/to/nuclei_resume.json
redaudit --nuclei-resume-latest
```

Resumed runs update the same scan folder and refresh reports in place.

### Nuclei Profiles and Coverage (v4.17+)

Nuclei has two independent controls in the wizard:

- **Profile (templates)**: `full`, `balanced`, `fast` controls which templates and severities run.
- **Full Coverage (targets)**: "Scan ALL detected HTTP ports?" controls how many HTTP URLs per host are scanned.
  - **No** (default for balanced/fast): Max 2 URLs per multi-port host (prioritizes 80/443).
  - **Yes** (default for full): Scan all detected HTTP ports per host (beyond 80/443).

These options are separate: profile defines template scope, full coverage defines target scope.

### Auto-Exclusion

The auditor's own IP addresses are automatically detected and excluded from the target list to prevent redundant self-scanning loopbacks.

### Agentless Verification (Optional)

When enabled, RedAudit runs lightweight Nmap scripts against hosts that expose SMB/RDP/LDAP/SSH/HTTP to enrich identity
data (OS hints, domain info, titles/headers, and basic fingerprints). This does **not** use credentials and is opt-in
to keep noise
predictable.

- Enable via wizard prompt or `--agentless-verify`.
- Limit scope with `--agentless-verify-max-targets` (default: 20).

---

## 6. Authenticated Scanning (Phase 4)

RedAudit v4.0+ supports authenticated scanning to retrieve high-fidelity data from target hosts, including OS versions, installed packages, and configurations.

### Supported Protocols

| Protocol | Target OS | Requirements | Discovery Features |
| :--- | :--- | :--- | :--- |
| **SSH** | Linux/Unix | Standard credentials (password or private key) | Precise OS (kernel), Installed Packages, Hostname, Uptime |
| **SMB/WMI** | Windows | `impacket` library, Administrator credentials | OS Version, Domain/Workgroup, Shares, Users |

### Prerequisites

- **SSH**: Requires `paramiko` (installed by the installer).
- **SMB/WMI**: Requires `impacket` (installed by the installer).
- **SNMP v3**: Requires `pysnmp` (installed by the installer).

  ```bash
  # If manual install needed:
  pip install paramiko impacket pysnmp
  ```

### Configuration

#### Interactive (Wizard)

When prompted "Enable authenticated scanning (SSH/SMB)?", select Yes. If saved credentials are detected, the wizard offers to load them first and then asks if you want to add more. The settings can be saved to a secure keyring or configuration file.

#### CLI Arguments

```bash
# SSH
sudo redaudit -t 192.168.1.10 --ssh-user root --ssh-key ~/.ssh/id_rsa
sudo redaudit -t 192.168.1.10 --ssh-user admin --ssh-pass "S3cr3t"

# SMB (Windows)
sudo redaudit -t 192.168.1.50 --smb-user Administrator --smb-pass "WinPass123" --smb-domain WORKGROUP
```

### Security Note

Credentials are used ONLY for scanning and are not stored in reports. If using `keyring` integration, they are stored in the system keyring.

---

## 7. CLI Reference (Complete)

Flags verified against `redaudit --help` (v4.5.2):

### Core

| Flag | Description |
| :--- | :--- |
| `-t, --target CIDR` | Targets (CIDR/IP/range), comma-separated |
| `-m, --mode {fast,normal,full}` | Scan intensity (default: normal) |
| `-o, --output DIR` | Output directory (default: `~/Documents/RedAuditReports`) |
| `-y, --yes` | Skip confirmation prompts |
| `-V, --version` | Print version and exit |

### Performance

| Flag | Description |
| :--- | :--- |
| `-j, --threads 1-16` | Concurrent host workers (auto-detected) |
| `--rate-limit SECONDS` | Delay between hosts (±30% jitter applied) |
| `--max-hosts N` | Limit hosts to scan |
| `--no-deep-scan` | Disable adaptive deep scan |
| `--low-impact-enrichment` | Low-impact enrichment (DNS/mDNS/SNMP) before TCP scanning |
| `--deep-scan-budget N` | Max hosts that can run aggressive deep scan per run (0 = unlimited) |
| `--identity-threshold N` | Minimum identity_score to skip deep scan (default: 3) |
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

### Authentication (Credentials)

| Flag | Description |
| :--- | :--- |
| `--auth-provider {env,keyring}` | Credential storage provider (env vars or system keyring) |
| `--ssh-user USER` | SSH username for authenticated scanning |
| `--ssh-key PATH` | Path to SSH private key |
| `--ssh-key-pass PASSPHRASE` | Passphrase for encrypted SSH private key |
| `--ssh-trust-keys` | Trust unknown SSH host keys (use with caution) |
| `--smb-user USER` | SMB/Windows username |
| `--smb-pass PASSWORD` | SMB/Windows password |
| `--smb-domain DOMAIN` | SMB/Windows domain |
| `--snmp-user USER` | SNMP v3 username |
| `--snmp-auth-proto {SHA,MD5,...}` | SNMP v3 authentication protocol |
| `--snmp-auth-pass PASSWORD` | SNMP v3 authentication password |
| `--snmp-priv-proto {AES,DES,...}` | SNMP v3 privacy protocol |
| `--snmp-priv-pass PASSWORD` | SNMP v3 privacy password |
| `--lynis` | Run Lynis hardening audit on Linux hosts (requires SSH) |
| `--credentials-file PATH` | JSON file with credentials list (auto-detects protocol) |
| `--generate-credentials-template` | Generate empty credentials template and exit |

#### Multi-Credential Support (Universal)

RedAudit supports **universal credential spraying**: you provide username/password pairs without specifying the protocol, and RedAudit automatically detects which protocol to use based on open ports discovered during scanning.

**How it works:**

1. You configure credentials via the wizard (Universal mode) or `--credentials-file`
2. RedAudit scans the network and discovers open ports
3. For each host, it maps open ports to protocols:
   - Port 22 → SSH
   - Port 445/139 → SMB
   - Port 161 → SNMP
   - Port 3389 → RDP
   - Port 5985/5986 → WinRM
4. It tries each credential until one succeeds (max 3 attempts per host to avoid lockouts)

**Legacy Mode (Single SSH/SMB):**

If you need to use a specific SSH key or a single credential pair for a specific protocol (e.g., legacy behavior), select **Advanced** mode in the wizard or use the specific flags (`--ssh-user`, `--ssh-key`, etc.). These will take precedence for that protocol or serve as a fallback if universal credentials fail.

**Using the wizard (recommended):**

```text
? Enable authenticated scanning? [y/n]: y
Credential configuration mode:
  [0] Universal (simple): auto-detect protocol
  [1] Advanced: configure SSH/SMB/SNMP separately
> 0

--- Credential 1 ---
? Username: admin
? Password (hidden): ****
? Add another credential? [y/n]: y

--- Credential 2 ---
? Username: root
? Password (hidden): ****
? Add another credential? [y/n]: n

Configured 2 credentials for automatic protocol detection.
```

**Using a credentials file:**

```bash
# Generate template
redaudit --generate-credentials-template

# Edit ~/.redaudit/credentials.json
{
  "credentials": [
    {"user": "admin", "pass": "admin123"},
    {"user": "root", "pass": "toor"},
    {"user": "administrator", "pass": "P@ssw0rd", "domain": "WORKGROUP"}
  ]
}

# Run scan with credentials
sudo redaudit -t 192.168.1.0/24 --credentials-file ~/.redaudit/credentials.json --yes
```

**Security considerations:**

- Credentials files are saved with `0600` permissions (owner-only read/write)
- Passwords are never logged in reports
- Use keyring for production environments (`--auth-provider keyring`)

### HyperScan

| Flag | Description |
| :--- | :--- |
| `--hyperscan-mode {auto,connect,syn}` | HyperScan mode: auto (default), connect, or syn |

### Reporting

| Flag | Description |
| :--- | :--- |
| `--html-report` | Generate interactive HTML dashboard |
| `--webhook URL` | POST alerts for high/critical findings |
| `--no-txt-report` | Skip TXT report generation |
| `--no-vuln-scan` | Skip nikto/web vulnerability scanning |
| `--nuclei` | Enable Nuclei template scanning (requires `nuclei`) |
| `--no-nuclei` | Disable Nuclei (overrides defaults) |
| `--nuclei-timeout N` | Nuclei batch timeout in seconds (default: 300; auto-raised to 900 in full coverage if lower) |
| `--nuclei-max-runtime MIN` | Max Nuclei runtime in minutes (0 = unlimited); creates a resume file when exceeded |
| `--profile {fast,balanced,full}` | Nuclei scan intensity (v4.11+) |
| `--nuclei-resume PATH` | Resume pending Nuclei targets from a resume file or scan folder |
| `--nuclei-resume-latest` | Resume latest pending Nuclei run from the default reports folder |

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
| `--proxy URL` | SOCKS5 proxy (socks5://host:port; requires proxychains4, TCP only) |
| `--lang {en,es}` | Interface language |
| `--no-color` | Disable colored output |
| `--save-defaults` | Save current settings to ~/.redaudit/config.json |
| `--defaults {ask,use,ignore}` | Control how persisted defaults are applied |
| `--use-defaults` | Use saved defaults without prompting |
| `--ignore-defaults` | Ignore saved defaults |
| `--skip-update-check` | Skip update check at startup |

**Note:** `--proxy` wraps external tools with `proxychains4` and only affects TCP connect-based probes. UDP/ARP/ICMP discovery remains direct.

---

## 8. Output Artifacts

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
| `run_manifest.json` | If encryption disabled | Session metadata + config/pipeline snapshot |
| `playbooks/*.md` | If encryption disabled | Remediation guides |
| `traffic_*.pcap` | If deep scan triggers and tcpdump available | Packet captures |
| `session_logs/session_*.log` | Always | Session logs (raw with ANSI) |
| `session_logs/session_*.txt` | Always | Session logs (clean text) |

### Encryption Behavior

When `--encrypt` is used:

- `.json` and `.txt` become `.json.enc` and `.txt.enc`
- A `.salt` file is created alongside each encrypted file
- **Plaintext artifacts are NOT generated:** HTML, JSONL, playbooks, and manifest files are skipped for security

**Evidence and pipeline transparency:**

- The main JSON includes per-finding evidence metadata (source tool, matched_at, raw output hash/ref when available).
- The HTML pipeline section exposes resolved Nmap args/timing, deep scan settings, HyperScan vs final summary, and authenticated scan outcomes when available.

**Decryption:**

```bash
python3 redaudit_decrypt.py /path/to/report.json.enc
```

---

## 9. Security Model

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

## 10. Integration

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

## 11. Troubleshooting

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| Permission denied | Running without sudo | Use `sudo redaudit` |
| nmap: command not found | Missing dependency | Run `sudo bash redaudit_install.sh` |
| Decryption failed: Invalid token | Wrong password or corrupted .salt | Verify password; ensure .salt file exists |
| Scan appears frozen | Deep scan or slow host | Check `session_logs/` for the active tool; reduce scope with `--max-hosts` |
| No playbooks generated | Encryption enabled | Playbooks require `--encrypt` to be disabled |

See [TROUBLESHOOTING.en.md](TROUBLESHOOTING.en.md) for complete error reference.

---

## 12. External Tools

RedAudit orchestrates (does not modify or install):

| Tool | Invocation Condition | Report Field |
| :--- | :--- | :--- |
| `nmap` | Always | `hosts[].ports` |
| `whatweb` | HTTP/HTTPS detected | `vulnerabilities[].whatweb` |
| `nikto` | HTTP/HTTPS + full mode | `vulnerabilities[].nikto_findings` |
| `sqlmap` | HTTP/HTTPS + full mode (v4.2+) | `vulnerabilities[].sqlmap_findings` |
| `zaproxy` | HTTP/HTTPS + full mode (if enabled) | `vulnerabilities[].zap_findings` |
| `testssl.sh` | HTTPS + full mode | `vulnerabilities[].testssl_analysis` |
| `nuclei` | HTTP/HTTPS + full mode (if installed and enabled) | `vulnerabilities[].nuclei_findings` |
| `searchsploit` | Services with version detected | `ports[].known_exploits` |
| `tcpdump` | Deep scan triggers | `deep_scan.pcap_capture` |
| `tshark` | After tcpdump capture | `deep_scan.tshark_summary` |

---

[Back to README](../README.md) | [Documentation Index](INDEX.md)
